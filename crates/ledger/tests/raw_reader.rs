//! The raw ledger reader, tested directly (the gate tests reach it through the command line): leaves, v1 and v2 checkpoint lines, every hostile file, and the exact limits. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::anchor::{sign_v2, AnyCheckpoint};
use entropa_core::merkle::{self, leaf_hash};
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::Probe;
use entropa_ledger::{read_raw, read_raw_with, LedgerError, MAX_CHECKPOINT_LINE, MAX_RECORD_LINE};
use std::path::PathBuf;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("raw-reader-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn probe() -> Probe {
    Probe::from_signing_key_hex(&hex::encode([8u8; 32])).unwrap()
}
fn put(d: &std::path::Path, file: &str, bytes: &[u8]) {
    std::fs::write(d.join(file), bytes).unwrap();
}
fn corrupt(r: Result<entropa_ledger::RawLedger, LedgerError>) -> String {
    match r {
        Err(LedgerError::Corrupt(m)) => m,
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn r1_leaves_and_both_checkpoint_kinds_are_read_in_order() {
    let d = dir("r1");
    let recs: Vec<Vec<u8>> = (0..3).map(|i| format!("rec-{i}").into_bytes()).collect();
    put(
        &d,
        "records.log",
        recs.iter()
            .map(|r| format!("{}\n", hex::encode(r)))
            .collect::<String>()
            .as_bytes(),
    );
    let mut log = TransparencyLog::new();
    log.append(&recs[0]);
    let v1 = log.checkpoint(&probe(), 10);
    let leaves: Vec<_> = recs.iter().map(|r| leaf_hash(r)).collect();
    let v2 = sign_v2(
        &probe(),
        1,
        &[0u8; 32],
        &merkle::root(&leaves).unwrap(),
        3,
        20,
    )
    .unwrap();
    put(
        &d,
        "checkpoints.log",
        format!(
            "{}\n{}\n",
            serde_json::to_string(&v1).unwrap(),
            serde_json::to_string(&v2).unwrap()
        )
        .as_bytes(),
    );
    let mut seen = vec![];
    let raw = read_raw_with(&d, &mut |b| seen.push(b.to_vec())).unwrap();
    assert_eq!(raw.leaves, leaves);
    assert_eq!(
        raw.checkpoints,
        vec![AnyCheckpoint::V1(v1), AnyCheckpoint::V2(v2)]
    );
    assert_eq!(
        seen, recs,
        "every record's bytes are handed to the callback in order"
    );
    assert_eq!(read_raw(&d).unwrap(), raw);
}
#[test]
fn r2_a_missing_file_is_empty_and_an_empty_directory_reads_as_an_empty_ledger() {
    let d = dir("r2");
    let raw = read_raw(&d).unwrap();
    assert!(raw.leaves.is_empty() && raw.checkpoints.is_empty());
}
#[test]
fn r3_every_hostile_record_file_is_corrupt_with_its_own_fixed_text() {
    let d = dir("r3");
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("partial last line", b"abcd".to_vec(), "partial line"),
        ("not hex", b"zz\n".to_vec(), "not hex"),
        ("odd hex", b"abc\n".to_vec(), "not hex"),
        ("NUL", b"ab\0cd\n".to_vec(), "not hex"),
        ("invalid UTF-8", b"\xff\xfe\n".to_vec(), "not hex"),
        ("empty line", b"\n".to_vec(), "empty or too large"),
        (
            "a record over 64 KiB",
            format!("{}\n", "ab".repeat(64 * 1024 + 1)).into_bytes(),
            "empty or too large",
        ),
        (
            "a line over the line limit",
            format!("{}\n", "a".repeat(MAX_RECORD_LINE + 1)).into_bytes(),
            "too long",
        ),
    ];
    for (what, bytes, text) in cases {
        put(&d, "records.log", &bytes);
        let m = corrupt(read_raw(&d));
        assert!(m.contains(text), "{what}: {m}");
        assert!(
            !m.contains("zz") && !m.contains("abcd"),
            "{what}: the message never echoes the input"
        );
    }
    // the exact boundary: 64 KiB of record bytes is accepted, the line limit is not reached
    put(
        &d,
        "records.log",
        format!("{}\n", "ab".repeat(64 * 1024)).as_bytes(),
    );
    assert_eq!(read_raw(&d).unwrap().leaves.len(), 1);
    // the limits are the documented numbers, not whatever the constants say
    assert_eq!((MAX_RECORD_LINE, MAX_CHECKPOINT_LINE), (131_074, 32 * 1024));
    // a line of exactly the line limit (valid hex, 65,537 bytes) is read and refused as a record that is too large; one digit more is a line that is too long
    put(
        &d,
        "records.log",
        format!("{}\n", "a".repeat(131_074)).as_bytes(),
    );
    assert!(corrupt(read_raw(&d)).contains("empty or too large"));
    put(
        &d,
        "records.log",
        format!("{}\n", "a".repeat(131_075)).as_bytes(),
    );
    assert!(corrupt(read_raw(&d)).contains("too long"));
    // the same limits for a last line that has no newline: exactly the limit is a partial line, one more is too long
    put(&d, "records.log", "a".repeat(131_074).as_bytes());
    assert!(corrupt(read_raw(&d)).contains("partial line"));
    put(&d, "records.log", "a".repeat(131_075).as_bytes());
    assert!(corrupt(read_raw(&d)).contains("too long"));
}
#[test]
fn r4_every_hostile_checkpoint_file_is_corrupt_and_the_line_limit_is_exact() {
    let d = dir("r4");
    for (what, bytes) in [
        ("partial", b"{}".to_vec()),
        ("not json", b"nope\n".to_vec()),
        ("wrong shape", b"{\"a\":1}\n".to_vec()),
        ("invalid UTF-8", b"\xff\xfe\n".to_vec()),
        ("v2 shape with a wrong field", b"{\"counter\":1}\n".to_vec()),
        ("an array", b"[]\n".to_vec()),
    ] {
        put(&d, "checkpoints.log", &bytes);
        let m = corrupt(read_raw(&d));
        assert!(!m.is_empty(), "{what}");
    }
    put(
        &d,
        "checkpoints.log",
        format!("{}\n", "x".repeat(MAX_CHECKPOINT_LINE)).as_bytes(),
    );
    assert!(
        corrupt(read_raw(&d)).contains("not valid"),
        "a line of exactly the limit is read (and is not JSON)"
    );
    put(
        &d,
        "checkpoints.log",
        format!("{}\n", "x".repeat(MAX_CHECKPOINT_LINE + 1)).as_bytes(),
    );
    assert!(
        corrupt(read_raw(&d)).contains("too long"),
        "one more byte is too long"
    );
}
#[test]
fn r5_an_unreadable_file_is_an_io_error_not_a_format_error() {
    let d = dir("r5");
    std::fs::create_dir_all(d.join("records.log")).unwrap(); // a directory where the file should be
    assert!(matches!(read_raw(&d), Err(LedgerError::Io(_))));
}

#[test]
fn r6_a_file_that_cannot_be_opened_for_another_reason_than_missing_is_an_io_error() {
    use std::os::unix::fs::PermissionsExt;
    let d = dir("r6");
    put(&d, "records.log", b"abcd\n");
    std::fs::set_permissions(
        d.join("records.log"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let can_open_anyway = std::fs::File::open(d.join("records.log")).is_ok(); // a superuser ignores the mode: the case cannot be shown there
    let r = read_raw(&d);
    std::fs::set_permissions(
        d.join("records.log"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    if can_open_anyway {
        return;
    }
    assert!(matches!(r, Err(LedgerError::Io(_))), "{r:?}");
}
