//! The append-only ledger store: file-backed and in-memory implementations behave the same.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::Probe;
use entropa_ledger::*;
use std::fs;

fn records(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("rec-{i}").into_bytes()).collect()
}

fn checkpoint_of(
    recs: &[Vec<u8>],
    probe: &Probe,
    ts: u64,
) -> entropa_core::transparency_log::Checkpoint {
    let mut log = TransparencyLog::new();
    for r in recs {
        log.append(r);
    }
    log.checkpoint(probe, ts)
}

fn behaviour<S: LedgerStore>(store: &mut S) {
    let recs = records(5);
    let probe = Probe::spawn();
    assert!(store.is_empty());
    for (i, r) in recs.iter().enumerate() {
        assert_eq!(must(store.append(r)), i);
    }
    assert_eq!(store.len(), 5);
    assert_eq!(store.record(2), Some(recs[2].clone()));
    assert_eq!(store.record(5), None);
    // checkpoints: must match the Merkle root of exactly that prefix and never shrink
    let cp3 = checkpoint_of(&recs[..3], &probe, START);
    must(store.put_checkpoint(&cp3));
    let cp5 = checkpoint_of(&recs, &probe, START + 1);
    must(store.put_checkpoint(&cp5));
    assert_eq!(store.checkpoints(), vec![cp3.clone(), cp5.clone()]);
    assert!(
        matches!(store.put_checkpoint(&cp3), Err(LedgerError::Invalid(_))),
        "a smaller checkpoint after a larger one"
    );
    let too_big = checkpoint_of(&records(9), &probe, START + 2);
    assert!(
        matches!(store.put_checkpoint(&too_big), Err(LedgerError::Invalid(_))),
        "covers more records than exist"
    );
    let other: Vec<Vec<u8>> = (0..5).map(|i| format!("alt-{i}").into_bytes()).collect();
    let wrong_root = checkpoint_of(&other, &probe, START + 3);
    assert!(
        matches!(
            store.put_checkpoint(&wrong_root),
            Err(LedgerError::Invalid(_))
        ),
        "root of different records"
    );
    assert_eq!(
        store.checkpoints().len(),
        2,
        "refused checkpoints are not stored"
    );
    // bounds on records
    assert!(matches!(store.append(b""), Err(LedgerError::Invalid(_))));
    assert!(matches!(
        store.append(&vec![1u8; 64 * 1024 + 1]),
        Err(LedgerError::Limit(_))
    ));
    assert_eq!(store.len(), 5, "refused records are not stored");
    // witness statements keep their order
    must(store.put_witness("{\"a\":1}"));
    must(store.put_witness("{\"b\":2}"));
    assert_eq!(
        store.witnesses(),
        vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()]
    );
    assert!(matches!(
        store.put_witness("not json"),
        Err(LedgerError::Invalid(_))
    ));
}

#[test]
fn s1_the_memory_store_follows_the_contract() {
    behaviour(&mut MemoryStore::default());
}

#[test]
fn s2_the_file_store_follows_the_same_contract() {
    let dir = tmpdir("contract");
    let mut s = must(FileStore::open(&dir));
    behaviour(&mut s);
}

#[test]
fn s3_the_file_store_survives_a_restart() {
    let dir = tmpdir("restart");
    let recs = records(4);
    let probe = Probe::spawn();
    let cp = checkpoint_of(&recs, &probe, START);
    {
        let mut s = must(FileStore::open(&dir));
        for r in &recs {
            must(s.append(r));
        }
        must(s.put_checkpoint(&cp));
        must(s.put_witness("{\"w\":1}"));
    }
    let s = must(FileStore::open(&dir));
    assert_eq!(s.len(), 4);
    assert_eq!(
        (0..4).map(|i| s.record(i).unwrap()).collect::<Vec<_>>(),
        recs
    );
    assert_eq!(s.checkpoints(), vec![cp]);
    assert_eq!(s.witnesses(), vec!["{\"w\":1}".to_string()]);
}

#[test]
fn s4_a_changed_record_is_caught_on_open_because_the_checkpoint_no_longer_matches() {
    let dir = tmpdir("tamper");
    let recs = records(3);
    let probe = Probe::spawn();
    {
        let mut s = must(FileStore::open(&dir));
        for r in &recs {
            must(s.append(r));
        }
        must(s.put_checkpoint(&checkpoint_of(&recs, &probe, START)));
    }
    let path = dir.join("records.log");
    let text = fs::read_to_string(&path).unwrap();
    let flipped = text.replacen('7', "6", 1);
    assert_ne!(text, flipped, "the test needs a hex digit to change");
    fs::write(&path, flipped).unwrap();
    assert!(matches!(
        expect_err(FileStore::open(&dir)),
        LedgerError::Corrupt(_)
    ));
}

#[test]
fn s5_a_torn_last_line_is_refused_not_silently_repaired() {
    for file in ["records.log", "checkpoints.log", "witnesses.log"] {
        let dir = tmpdir("torn");
        {
            let mut s = must(FileStore::open(&dir));
            must(s.append(b"rec-0"));
            must(s.put_witness("{\"w\":1}"));
        }
        let path = dir.join(file);
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        text.push_str("abc"); // no trailing newline: a write that did not finish
        fs::write(&path, text).unwrap();
        assert!(
            matches!(expect_err(FileStore::open(&dir)), LedgerError::Corrupt(_)),
            "{file}"
        );
    }
}

#[test]
fn s6_only_one_writer_may_have_the_store_open() {
    let dir = tmpdir("lock");
    let first = must(FileStore::open(&dir));
    assert!(matches!(
        expect_err(FileStore::open(&dir)),
        LedgerError::Io(_)
    ));
    drop(first);
    must(FileStore::open(&dir));
}

#[test]
fn s7_a_file_store_never_rewrites_what_it_wrote() {
    let dir = tmpdir("append-only");
    let mut s = must(FileStore::open(&dir));
    must(s.append(b"rec-0"));
    let before = fs::read(dir.join("records.log")).unwrap();
    must(s.append(b"rec-1"));
    let after = fs::read(dir.join("records.log")).unwrap();
    assert!(
        after.starts_with(&before),
        "the earlier bytes are untouched"
    );
    assert!(after.len() > before.len());
}
