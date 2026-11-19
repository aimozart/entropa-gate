//! Anchoring: the pre-registration's hash is appended as ONE hash-only record to a local ledger; `check` is true only for a ledger that verifies and holds it. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_check::anchor::{check, record};
use entropa_core::transparency_log::decode_record;
use entropa_ledger::{decode_event, FileStore, LabelCode, LedgerStore};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const PREREG: &str =
    r#"{"schema":"entropa-prereg-v1","stage":"T1","note":"stand-in text for the record"}"#;

fn node(name: &str, byte: &str) -> PathBuf {
    let d = scratch(name);
    let f = d.join("platinum.key");
    std::fs::write(&f, format!("{}\n", byte.repeat(32))).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    d
}
fn expected_subject(prereg: &str) -> String {
    let sha = entropa_check::sha256_hex(prereg.as_bytes());
    let detail = format!("entropa-prereg-v1|{sha}");
    let run_id = format!("prereg-{}", &sha[..24]);
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-evidence-subject-v1\0");
    for part in [detail.as_bytes(), run_id.as_bytes()] {
        h.update(&(part.len() as u64).to_be_bytes());
        h.update(part);
    }
    hex::encode(h.finalize().as_bytes())
}

#[test]
fn a1_record_then_check_and_the_record_is_the_documented_hash_only_event() {
    let d = node("a1", "7a");
    assert!(!check(&d, PREREG), "nothing is anchored yet");
    assert_eq!(record(&d, PREREG).unwrap(), 0);
    assert!(check(&d, PREREG));
    let store = FileStore::open(&d.join("evidence-ledger")).unwrap();
    assert_eq!(store.len(), 1);
    let (payload, _) = decode_record(&store.record(0).unwrap()).unwrap();
    let ev = decode_event(&payload).unwrap();
    assert_eq!(ev.fields.label, LabelCode::PreregCommitted);
    assert!(
        ev.fields.ts > 1_700_000_000,
        "the record carries the real time, not a placeholder: {}",
        ev.fields.ts
    );
    assert_eq!(
        ev.fields.subject_hash,
        expected_subject(PREREG),
        "the subject hash matches the independent BLAKE3 recomputation"
    );
}

#[test]
fn a2_check_is_false_for_other_text_other_ledgers_and_a_damaged_ledger() {
    let d = node("a2", "7a");
    record(&d, PREREG).unwrap();
    assert!(
        !check(&d, &PREREG.replace("T1", "T2")),
        "a different record is not anchored"
    );
    let other = node("a2b", "7a");
    assert!(!check(&other, PREREG), "an empty ledger holds nothing");
    assert!(
        !check(&d.join("nope"), PREREG),
        "a missing directory holds nothing"
    );
    // damage the ledger: flip one byte of the records file
    let dir = d.join("evidence-ledger");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    let target = files
        .iter()
        .find(|p| std::fs::metadata(p).unwrap().len() > 8)
        .expect("a non-empty ledger file")
        .clone();
    let mut bytes = std::fs::read(&target).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&target, bytes).unwrap();
    assert!(
        !check(&d, PREREG),
        "a ledger that no longer verifies anchors nothing"
    );
}

#[test]
fn a3_a_wrong_key_does_not_verify_and_a_loose_key_or_missing_key_is_refused() {
    let d = node("a3", "7a");
    record(&d, PREREG).unwrap();
    // the same ledger under another key: it was signed by 7a, the node now says 7b
    std::fs::write(d.join("platinum.key"), format!("{}\n", "7b".repeat(32))).unwrap();
    assert!(!check(&d, PREREG));
    let loose = node("a3b", "7a");
    std::fs::set_permissions(
        loose.join("platinum.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(record(&loose, PREREG).is_err());
    assert!(!loose.join("evidence-ledger").exists(), "nothing written");
    let nokey = scratch("a3c");
    assert!(record(&nokey, PREREG).is_err());
}

#[test]
fn a4_a_second_anchor_of_the_same_record_is_refused_and_the_ledger_holds_only_hashes() {
    let d = node("a4", "7a");
    record(&d, PREREG).unwrap();
    let e = record(&d, PREREG).unwrap_err();
    assert!(e.0.contains("already anchored"), "{e}");
    assert_eq!(
        FileStore::open(&d.join("evidence-ledger")).unwrap().len(),
        1
    );
    // no byte of the ledger holds the record's sha256 text or the record text
    let sha = entropa_check::sha256_hex(PREREG.as_bytes());
    for e in std::fs::read_dir(d.join("evidence-ledger")).unwrap() {
        let b = std::fs::read(e.unwrap().path()).unwrap();
        let t = String::from_utf8_lossy(&b);
        assert!(
            !t.contains(&sha) && !t.contains("stand-in text") && !t.contains("entropa-prereg-v1|"),
            "the ledger must hold the hash only"
        );
    }
    // a second, different record is a second entry in the same ledger
    record(&d, &PREREG.replace("T1", "T2")).unwrap();
    assert!(check(&d, PREREG) && check(&d, &PREREG.replace("T1", "T2")));
}

fn _unused(_: &Path) {}

#[test]
fn a5_a_record_with_another_label_but_the_same_detail_is_not_an_anchor() {
    use entropa_ledger::{
        evidence_fields, ControlCode, Decision, EvidenceRecord, Kind, ReasonCode,
    };
    let d = node("a5", "7a");
    let probe = entropa_release::cli::load_key(&d.join("platinum.key")).unwrap();
    let sha = entropa_check::sha256_hex(PREREG.as_bytes());
    let detail = format!("entropa-prereg-v1|{sha}");
    let run_id = format!("prereg-{}", &sha[..24]);
    // a DEPLOY record that happens to carry the very same detail and run id: same subject hash, different label
    let f = evidence_fields(&EvidenceRecord {
        kind: Kind::EvidenceChange,
        label: LabelCode::Deploy,
        decision: Decision::Info,
        reason: ReasonCode::None,
        control: ControlCode::Hitrust10Sdlc,
        total: 1,
        passed: 1,
        flagged: 0,
        detail: &detail,
        run_id: &run_id,
        ts: 1_700_000_000,
        key_id: entropa_approvals::key_id(&probe.pubkey_hex()),
    })
    .unwrap();
    entropa_nodecore::append(&d, "evidence-ledger", &probe, &f).unwrap();
    assert!(!check(&d, PREREG), "only a prereg_committed record anchors");
    // and recording the real anchor is still allowed (the duplicate rule is about anchors, not other labels)
    assert!(record(&d, PREREG).is_ok());
    assert!(check(&d, PREREG));
}
