//! RO-VERIFY (found while running the reader command in a container with read-only mounts): `FileStore::open` creates the directory and a writer lock file, so a ledger on read-only
//! media, or one that a writer holds open, cannot be verified. `FileStore::open_read_only` must load and verify without creating anything, and must refuse every write.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_ledger::{FileStore, LedgerStore};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ro-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn probe() -> Probe {
    Probe::from_signing_key_hex(&format!("{:02x}", 4u8).repeat(32)).unwrap()
}
/// A real signed ledger of n records written through the node core (so the verifier path is the real one).
fn ledger(tag: &str, n: u32) -> (PathBuf, String) {
    let d = scratch(tag);
    let p = probe();
    let pk = p.pubkey_hex();
    for i in 0..n {
        let req = format!(
            r#"{{"kind":"evidence.policy","label":"policy_verdict","decision":"allow","reason":"within_limits","control":"hitrust_01_access_control","total":1,"passed":1,"flagged":0,"detail":"d{i}","run_id":"{i:064x}","ts":{}}}"#,
            1_800_000_000 + i
        );
        let f = entropa_nodecore::evidence_event(&req, &pk).unwrap();
        entropa_nodecore::append(&d, "evidence-ledger", &p, &f).unwrap();
    }
    (d, pk)
}
fn make_read_only(dir: &Path) {
    for e in walk(dir) {
        let m = if e.is_dir() { 0o555 } else { 0o444 };
        std::fs::set_permissions(&e, std::fs::Permissions::from_mode(m)).unwrap();
    }
}
fn walk(d: &Path) -> Vec<PathBuf> {
    let mut v = vec![];
    for e in std::fs::read_dir(d).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            v.extend(walk(&p));
        }
        v.push(p);
    }
    v.push(d.to_path_buf());
    v
}
fn names(d: &Path) -> Vec<String> {
    let mut n: Vec<String> = std::fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    n.sort();
    n
}

#[test]
fn ro1_a_read_only_directory_loads_and_nothing_is_created() {
    let (d, _) = ledger("ro1", 6);
    let store_dir = d.join("evidence-ledger");
    make_read_only(&d);
    let before = names(&store_dir);
    let s = FileStore::open_read_only(&store_dir).expect("a read-only directory must load");
    assert_eq!((s.len(), s.checkpoints().len()), (6, 6));
    assert_eq!(names(&store_dir), before, "open_read_only created a file");
    drop(s);
    assert_eq!(
        names(&store_dir),
        before,
        "dropping the store changed the directory"
    );
}

#[test]
fn ro2_a_missing_directory_is_an_error_and_is_not_created() {
    let d = scratch("ro2");
    let missing = d.join("nope");
    assert!(FileStore::open_read_only(&missing).is_err());
    assert!(!missing.exists(), "the directory was created");
}

#[test]
fn ro3_it_works_while_a_writer_holds_the_store_and_leaves_the_writers_lock_alone() {
    let (d, _) = ledger("ro3", 4);
    let store_dir = d.join("evidence-ledger");
    let w = FileStore::open(&store_dir).unwrap();
    assert!(store_dir.join(".lock").exists());
    let r = FileStore::open_read_only(&store_dir).expect("a reader must not need the writer lock");
    assert_eq!(r.len(), 4);
    drop(r);
    assert!(
        store_dir.join(".lock").exists(),
        "the reader removed the writer's lock"
    );
    drop(w);
    assert!(!store_dir.join(".lock").exists());
    // and a second writer is still refused while the first holds it
    let w1 = FileStore::open(&store_dir).unwrap();
    assert!(FileStore::open(&store_dir).is_err());
    drop(w1);
}

#[test]
fn ro4_every_write_on_a_read_only_store_is_refused_and_changes_nothing() {
    let (d, pk) = ledger("ro4", 3);
    let store_dir = d.join("evidence-ledger");
    let mut s = FileStore::open_read_only(&store_dir).unwrap();
    let rec = s.record(0).unwrap();
    let cp = s.checkpoints()[0].clone();
    let sizes = |p: &Path| {
        ["records.log", "checkpoints.log"].map(|f| std::fs::metadata(p.join(f)).unwrap().len())
    };
    let before = sizes(&store_dir);
    assert!(s.append(&rec).is_err());
    assert!(s.put_checkpoint(&cp).is_err());
    assert!(s.put_witness("{}").is_err());
    assert_eq!(sizes(&store_dir), before);
    assert_eq!(s.len(), 3);
    let _ = pk;
}

#[test]
fn ro5_the_node_verifier_and_the_reader_command_verify_a_read_only_ledger() {
    let (d, pk) = ledger("ro5", 8);
    make_read_only(&d);
    let t = entropa_nodecore::verify_ledger(
        &d,
        "evidence-ledger",
        entropa_ledger::Kind::is_evidence,
        &pk,
    )
    .unwrap();
    assert_eq!(t, "OK records=8 checkpoints=8");
    assert!(!d.join("evidence-ledger/.lock").exists());
}

#[test]
fn ro6_a_corrupt_ledger_is_refused_in_read_only_mode_for_the_right_reason() {
    let (d, pk) = ledger("ro6", 5);
    let p = d.join("evidence-ledger/records.log");
    let mut b = std::fs::read(&p).unwrap();
    b[60] = if b[60] == b'0' { b'1' } else { b'0' };
    std::fs::write(&p, b).unwrap();
    make_read_only(&d);
    let e = entropa_nodecore::verify_ledger(
        &d,
        "evidence-ledger",
        entropa_ledger::Kind::is_evidence,
        &pk,
    )
    .unwrap_err();
    assert!(
        e.to_string().contains("does not match the records")
            || e.to_string().contains("not hex")
            || e.to_string().contains("signature"),
        "refused for another reason: {e}"
    );
    assert!(
        !e.to_string().contains("lock"),
        "refused because of the lock, not the content: {e}"
    );
}

#[test]
fn ro7_a_node_directory_without_the_ledger_directory_keeps_its_old_answer_and_creates_nothing() {
    // accepted behaviour (platinum tests ec2 and others): verifying a fresh node says OK records=0; before this change it did so by CREATING the directory
    let d = scratch("ro7");
    let before = names(&d);
    let t = entropa_nodecore::verify_ledger(
        &d,
        "evidence-ledger",
        entropa_ledger::Kind::is_evidence,
        &format!("{:02x}", 1u8).repeat(1952),
    )
    .unwrap();
    assert_eq!(t, "OK records=0 checkpoints=0");
    assert_eq!(names(&d), before, "verify created something");
    assert!(!d.join("evidence-ledger").exists());
}
