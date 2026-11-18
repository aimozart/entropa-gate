//! LEDGER-INCREMENTAL red tests (a stage record (not published), L1 to L6). The expected values come from the unchanged verifier (`entropa_platinum::verify_evidence_with`, `FileStore::open`)
//! and from an independent Merkle root over the stored records. Against the red stub every append answers "not implemented".
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::merkle::{leaf_hash, root};
use entropa_core::Probe;
use entropa_ledger::{
    evidence_fields, ControlCode, Decision, EventFields, EvidenceRecord, FileStore, Kind,
    LabelCode, LedgerStore, ReasonCode,
};
use entropa_tiers::append::{Failpoint, IncrementalLedger};
use std::path::{Path, PathBuf};

fn seed_probe(tag: &str) -> Probe {
    Probe::from_signing_key_hex(&hex::encode(
        blake3::hash(format!("incremental-{tag}").as_bytes()).as_bytes(),
    ))
    .unwrap()
}
fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("inc-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(d.join("evidence-ledger")).unwrap();
    d
}
fn fields(i: u64, key_id: &str) -> EventFields {
    let detail = format!("detail-{i}");
    let run = format!("{i:064x}");
    evidence_fields(&EvidenceRecord {
        kind: Kind::parse("evidence.policy").unwrap(),
        label: LabelCode::parse("policy_verdict").unwrap(),
        decision: if i.is_multiple_of(2) {
            Decision::Allow
        } else {
            Decision::Deny
        },
        reason: ReasonCode::parse("within_limits").unwrap(),
        control: ControlCode::parse("hitrust_01_access_control").unwrap(),
        total: 1,
        passed: i % 2,
        flagged: 0,
        detail: &detail,
        run_id: &run,
        ts: 1_800_000_000 + i,
        key_id: key_id.to_string(),
    })
    .unwrap()
}
fn key_id(p: &Probe) -> String {
    entropa_approvals::key_id(&p.pubkey_hex())
}
fn pubkey(tag: &str) -> String {
    seed_probe(tag).pubkey_hex()
}
fn writer(d: &Path, tag: &str) -> IncrementalLedger {
    IncrementalLedger::new(d.to_path_buf(), Box::new(seed_probe(tag)))
}
/// Verify with the unchanged verifier, and check the last checkpoint root against an independent Merkle root of the stored records.
fn verify(d: &Path, tag: &str) -> usize {
    let out = entropa_platinum::verify_evidence_with(d, &pubkey(tag))
        .unwrap_or_else(|e| panic!("does not verify: {e}"));
    let n: usize = out
        .split("records=")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let store = FileStore::open(&d.join("evidence-ledger")).unwrap();
    let leaves: Vec<_> = (0..store.len())
        .map(|i| leaf_hash(&store.record(i).unwrap()))
        .collect();
    let cps = store.checkpoints();
    assert_eq!(
        cps.last().unwrap().root,
        root(&leaves).unwrap(),
        "the last checkpoint root equals an independent root"
    );
    assert_eq!(cps.last().unwrap().size, n);
    n
}

#[test]
fn i1_the_appended_ledger_verifies_and_every_checkpoint_root_is_the_independent_root() {
    for n in [1u64, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 33, 100] {
        let d = dir(&format!("i1-{n}"));
        let w = writer(&d, "i1");
        let kid = key_id(&seed_probe("i1"));
        for i in 0..n {
            assert_eq!(w.append_event(&fields(i, &kid)).unwrap(), i as usize);
        }
        assert_eq!(verify(&d, "i1"), n as usize, "size {n}");
        assert_eq!(w.len().unwrap(), n as usize);
    }
}

#[test]
fn i2_a_stale_writer_notices_another_writers_appends_and_the_result_verifies() {
    let d = dir("i2");
    let (a, b) = (writer(&d, "i2"), writer(&d, "i2"));
    let kid = key_id(&seed_probe("i2"));
    for i in 0..30u64 {
        let w = if i % 3 == 0 { &a } else { &b };
        assert_eq!(
            w.append_event(&fields(i, &kid)).unwrap(),
            i as usize,
            "record {i}"
        );
    }
    assert_eq!(verify(&d, "i2"), 30);
}

#[test]
fn i3_a_kill_between_the_record_and_its_checkpoint_is_repaired_by_the_next_open() {
    let d = dir("i3");
    let kid = key_id(&seed_probe("i3"));
    let w = writer(&d, "i3");
    for i in 0..5u64 {
        w.append_event(&fields(i, &kid)).unwrap();
    }
    let broken = writer(&d, "i3").with_failpoint(Failpoint::AfterRecord);
    assert!(
        broken.append_event(&fields(5, &kid)).is_err(),
        "the failpoint reports the failure"
    );
    assert!(
        entropa_platinum::verify_evidence_with(&d, &pubkey("i3")).is_err(),
        "a record without its checkpoint does not verify"
    );
    // the next writer repairs first, then appends
    let again = writer(&d, "i3");
    assert_eq!(
        again.append_event(&fields(6, &kid)).unwrap(),
        6,
        "the unreported record is present: the new one is number 6"
    );
    assert_eq!(verify(&d, "i3"), 7);
}

#[test]
fn i4_a_partial_last_line_is_refused_and_the_file_is_left_alone() {
    let d = dir("i4");
    let kid = key_id(&seed_probe("i4"));
    let w = writer(&d, "i4");
    for i in 0..3u64 {
        w.append_event(&fields(i, &kid)).unwrap();
    }
    let path = d.join("evidence-ledger/records.log");
    let mut text = std::fs::read(&path).unwrap();
    text.extend_from_slice(b"deadbeef"); // a partial line: no newline
    std::fs::write(&path, &text).unwrap();
    let before = std::fs::read(&path).unwrap();
    let fresh = writer(&d, "i4");
    let e = fresh.append_event(&fields(3, &kid)).unwrap_err();
    assert!(e.contains("partial"), "{e}");
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing was written");
}

#[test]
fn i5_a_failing_signer_writes_nothing() {
    struct Failing(Probe);
    impl entropa_core::CheckpointSigner for Failing {
        fn algorithm(&self) -> &'static str {
            self.0.algorithm()
        }
        fn pubkey_hex(&self) -> String {
            self.0.pubkey_hex()
        }
        fn try_sign_hex(&self, _: &[u8]) -> Result<String, entropa_core::SignError> {
            Err(entropa_core::SignError::Backend("signer down".into()))
        }
    }
    let d = dir("i5");
    let kid = key_id(&seed_probe("i5"));
    let good = writer(&d, "i5");
    good.append_event(&fields(0, &kid)).unwrap();
    let bad = IncrementalLedger::new(d.clone(), Box::new(Failing(seed_probe("i5"))));
    assert!(bad.append_event(&fields(1, &kid)).is_err());
    assert_eq!(verify(&d, "i5"), 1);
    // the good writer's in-memory state is still right after the failure of another writer
    assert_eq!(good.append_event(&fields(1, &kid)).unwrap(), 1);
    assert_eq!(verify(&d, "i5"), 2);
}

#[test]
fn i6_a_writer_refuses_while_a_filestore_lock_exists() {
    let d = dir("i6");
    let kid = key_id(&seed_probe("i6"));
    std::fs::write(d.join("evidence-ledger/.lock"), b"").unwrap(); // someone has the store open
    let w = writer(&d, "i6");
    let e = w.append_event(&fields(0, &kid)).unwrap_err();
    assert!(e.contains("open elsewhere") || e.contains("locked"), "{e}");
    assert!(
        !d.join("evidence-ledger/records.log").exists()
            || std::fs::read(d.join("evidence-ledger/records.log"))
                .unwrap()
                .is_empty()
    );
}

// ---- two processes: the child side runs only when the environment names a directory
#[test]
fn child_appends_then_optionally_aborts() {
    let Ok(dirs) = std::env::var("INC_CHILD_DIR") else {
        return;
    };
    let tag = std::env::var("INC_CHILD_TAG").unwrap();
    let count: u64 = std::env::var("INC_CHILD_COUNT").unwrap().parse().unwrap();
    let base: u64 = std::env::var("INC_CHILD_BASE").unwrap().parse().unwrap();
    let kid = key_id(&seed_probe(&tag));
    let mut w = writer(Path::new(&dirs), &tag);
    if std::env::var("INC_CHILD_ABORT").is_ok() {
        w = w.with_failpoint(Failpoint::AbortAfterRecord);
    }
    for i in 0..count {
        w.append_event(&fields(base + i, &kid)).unwrap();
    }
}
fn spawn_child(
    d: &Path,
    tag: &str,
    base: u64,
    count: u64,
    abort: bool,
) -> std::process::ExitStatus {
    let mut c = std::process::Command::new(std::env::current_exe().unwrap());
    c.args([
        "child_appends_then_optionally_aborts",
        "--exact",
        "--nocapture",
    ])
    .env("INC_CHILD_DIR", d)
    .env("INC_CHILD_TAG", tag)
    .env("INC_CHILD_BASE", base.to_string())
    .env("INC_CHILD_COUNT", count.to_string());
    if abort {
        c.env("INC_CHILD_ABORT", "1");
    }
    c.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
}

#[test]
fn i7_two_processes_take_turns_and_the_ledger_verifies() {
    let d = dir("i7");
    for round in 0..6u64 {
        assert!(spawn_child(&d, "i7", round * 40, 20, false).success());
        assert!(spawn_child(&d, "i7", round * 40 + 20, 20, false).success());
    }
    assert_eq!(verify(&d, "i7"), 240);
}

#[test]
fn i8_a_killed_process_leaves_no_stale_lock_and_the_ledger_resumes_and_verifies() {
    let d = dir("i8");
    assert!(spawn_child(&d, "i8", 0, 10, false).success());
    let killed = spawn_child(&d, "i8", 10, 5, true);
    assert!(
        !killed.success(),
        "the child aborted after a record and before its checkpoint"
    );
    // no stale lock to remove by hand: the next writer just works, repairs first and appends
    let kid = key_id(&seed_probe("i8"));
    let w = writer(&d, "i8");
    w.append_event(&fields(100, &kid)).unwrap();
    let n = verify(&d, "i8");
    assert_eq!(
        n, 12,
        "10 + the record written before the abort + the new one"
    );
}

#[test]
#[ignore]
fn append_latency_flat_at_1_300_3000_and_30000() {
    let d = dir("perf");
    let kid = key_id(&seed_probe("perf"));
    let w = writer(&d, "perf");
    let mut line = String::new();
    for n in 1..=30_000u64 {
        let t = std::time::Instant::now();
        w.append_event(&fields(n, &kid)).unwrap();
        let us = t.elapsed().as_micros();
        if n == 1 || n == 300 || n == 3000 || n == 30_000 {
            line.push_str(&format!("append #{n}: {us} us\n"));
        }
    }
    eprintln!("{line}");
}

#[test]
fn i9_an_unusable_directory_is_an_error_that_names_what_failed() {
    // `evidence-ledger` exists as a FILE: nothing can be created in it
    let d = std::env::temp_dir().join(format!("inc-i9-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("evidence-ledger"), b"not a directory").unwrap();
    let w = writer(&d, "i9");
    let e = w
        .append_event(&fields(0, &key_id(&seed_probe("i9"))))
        .unwrap_err();
    assert!(e.contains("create dir") || e.contains("lock file"), "{e}");
    assert!(e.contains(':'), "the error names the kind of failure: {e}");
    assert_eq!(
        std::fs::read(d.join("evidence-ledger")).unwrap(),
        b"not a directory"
    );
}

#[test]
fn i10_repair_makes_a_killed_ledger_verify_without_appending_and_does_it_once() {
    let d = dir("i10");
    let kid = key_id(&seed_probe("i10"));
    let w = writer(&d, "i10");
    for i in 0..4u64 {
        w.append_event(&fields(i, &kid)).unwrap();
    }
    let broken = writer(&d, "i10").with_failpoint(Failpoint::AfterRecord);
    assert!(broken.append_event(&fields(4, &kid)).is_err());
    assert!(entropa_platinum::verify_evidence_with(&d, &pubkey("i10")).is_err());
    let r = writer(&d, "i10");
    assert_eq!(r.repair(), Ok(true), "a checkpoint was missing");
    let out = entropa_platinum::verify_evidence_with(&d, &pubkey("i10")).unwrap();
    assert!(
        out.contains("records=5 checkpoints=5"),
        "the repair adds exactly one checkpoint: {out}"
    );
    assert_eq!(r.repair(), Ok(false), "nothing to repair the second time");
    let out = entropa_platinum::verify_evidence_with(&d, &pubkey("i10")).unwrap();
    assert!(out.contains("records=5 checkpoints=5"), "{out}");
}

#[test]
fn i11_len_and_is_empty_follow_the_files() {
    let d = dir("i11");
    let kid = key_id(&seed_probe("i11"));
    let w = writer(&d, "i11");
    assert_eq!((w.len(), w.is_empty()), (Ok(0), Ok(true)), "no file yet");
    w.append_event(&fields(0, &kid)).unwrap();
    assert_eq!((w.len(), w.is_empty()), (Ok(1), Ok(false)));
    // an unreadable records.log (a directory) is an error, not "empty"
    let d2 = std::env::temp_dir().join(format!("inc-i11b-{}", std::process::id()));
    std::fs::create_dir_all(d2.join("evidence-ledger/records.log")).unwrap();
    assert!(writer(&d2, "i11").len().is_err());
}

#[test]
fn i12_the_writer_lock_is_waited_for_and_given_up_on_at_the_timeout() {
    use std::time::{Duration, Instant};
    let d = dir("i12");
    let kid = key_id(&seed_probe("i12"));
    let held = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(d.join("evidence-ledger/.append.lock"))
        .unwrap();
    held.lock().unwrap();
    let w = writer(&d, "i12").with_lock_timeout(Duration::from_millis(300));
    let t = Instant::now();
    let e = w.append_event(&fields(0, &kid)).unwrap_err();
    assert!(e.contains("locked"), "{e}");
    assert!(
        t.elapsed() >= Duration::from_millis(250),
        "it waited for the timeout: {:?}",
        t.elapsed()
    );
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "and then gave up: {:?}",
        t.elapsed()
    );
    // released within the timeout: the write goes through
    let w2 = writer(&d, "i12").with_lock_timeout(Duration::from_secs(5));
    std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(Duration::from_millis(150));
            held.unlock().unwrap();
        });
        assert_eq!(w2.append_event(&fields(0, &kid)).unwrap(), 0);
    });
}
