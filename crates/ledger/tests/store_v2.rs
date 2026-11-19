//! INS2 slice 3 red tests: the store keeps v1 and v2 checkpoints (a ledger may start v1 and continue v2; a v1 after a v2 is refused; the v2 counter and chain are enforced at write and at load).
//! Fixed test seeds; synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::anchor::{sign_v2, AnyCheckpoint, CheckpointV2};
use entropa_core::merkle;
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::Probe;
use entropa_ledger::{FileStore, LedgerStore, MemoryStore};
use std::path::PathBuf;

fn probe() -> Probe {
    Probe::from_signing_key_hex(&hex::encode([6u8; 32])).unwrap()
}
fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("store-v2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}
fn rec(i: usize) -> Vec<u8> {
    format!("record-{i}").into_bytes()
}
fn leaves(n: usize) -> Vec<merkle::Hash> {
    (0..n).map(|i| merkle::leaf_hash(&rec(i))).collect()
}
fn v1(n: usize, ts: u64) -> entropa_core::transparency_log::Checkpoint {
    let mut log = TransparencyLog::new();
    for i in 0..n {
        log.append(&rec(i));
    }
    log.checkpoint(&probe(), ts)
}
fn v2(counter: u64, prev: &merkle::Hash, n: usize, ts: u64) -> CheckpointV2 {
    sign_v2(
        &probe(),
        counter,
        prev,
        &merkle::root(&leaves(n)).unwrap(),
        n,
        ts,
    )
    .unwrap()
}
fn filled(s: &mut impl LedgerStore, n: usize) {
    for i in 0..n {
        s.append(&rec(i)).unwrap();
    }
}

#[test]
fn s1_a_v2_checkpoint_is_stored_reloaded_and_shown_both_ways() {
    let d = dir("s1");
    let first = v2(1, &[0u8; 32], 3, 100);
    let second = v2(2, &first.chain_digest(), 5, 200);
    {
        let mut s = FileStore::open(&d).unwrap();
        filled(&mut s, 5);
        s.put_checkpoint_v2(&first).unwrap();
        s.put_checkpoint_v2(&second).unwrap();
    }
    let text = std::fs::read_to_string(d.join("checkpoints.log")).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(
        text.lines().all(|l| l.contains("\"counter\"")),
        "v2 lines carry the counter: {text}"
    );
    let s = FileStore::open_read_only(&d).unwrap();
    assert_eq!(
        s.any_checkpoints(),
        vec![
            AnyCheckpoint::V2(first.clone()),
            AnyCheckpoint::V2(second.clone())
        ]
    );
    let view = s.checkpoints();
    assert_eq!(view.len(), 2);
    assert_eq!(
        (view[1].size, view[1].root, view[1].timestamp),
        (5, second.root, 200)
    );
}
#[test]
fn s2_the_counter_and_the_previous_digest_are_enforced_at_write() {
    let d = dir("s2");
    let mut s = FileStore::open(&d).unwrap();
    filled(&mut s, 5);
    let zero = [0u8; 32];
    assert!(
        s.put_checkpoint_v2(&v2(2, &zero, 3, 100)).is_err(),
        "the first v2 counter is 1"
    );
    assert!(
        s.put_checkpoint_v2(&v2(1, &[9u8; 32], 3, 100)).is_err(),
        "the first previous digest is zero"
    );
    let first = v2(1, &zero, 3, 100);
    s.put_checkpoint_v2(&first).unwrap();
    assert!(
        s.put_checkpoint_v2(&v2(3, &first.chain_digest(), 4, 150))
            .is_err(),
        "a counter may not skip"
    );
    assert!(
        s.put_checkpoint_v2(&v2(1, &first.chain_digest(), 4, 150))
            .is_err(),
        "a counter may not repeat"
    );
    assert!(
        s.put_checkpoint_v2(&v2(2, &zero, 4, 150)).is_err(),
        "the previous digest must be the chain digest of the last v2"
    );
    s.put_checkpoint_v2(&v2(2, &first.chain_digest(), 3, 150))
        .unwrap(); // the same size again is fine: the counter still moves
    assert_eq!(s.any_checkpoints().len(), 2);
}
#[test]
fn s3_the_old_rules_still_apply_to_v2_and_a_v1_may_not_follow_a_v2() {
    let d = dir("s3");
    let mut s = FileStore::open(&d).unwrap();
    filled(&mut s, 5);
    let zero = [0u8; 32];
    assert!(
        s.put_checkpoint_v2(&v2(1, &zero, 9, 100)).is_err(),
        "more records than exist"
    );
    let mut wrong_root = v2(1, &zero, 3, 100);
    wrong_root.root = [1u8; 32];
    assert!(
        s.put_checkpoint_v2(&wrong_root).is_err(),
        "root of another prefix"
    );
    s.put_checkpoint(&v1(2, 50)).unwrap(); // v1 first is fine (the transition)
    let a = v2(1, &zero, 4, 100);
    s.put_checkpoint_v2(&a).unwrap(); // then v2: the chain starts at the switch
    assert!(
        s.put_checkpoint(&v1(5, 300)).is_err(),
        "a v1 after a v2 is a downgrade"
    );
    assert!(
        s.put_checkpoint_v2(&v2(2, &a.chain_digest(), 3, 200))
            .is_err(),
        "a v2 may not be older than the previous checkpoint"
    );
    assert_eq!(s.any_checkpoints().len(), 2);
}
#[test]
fn s4_a_ledger_on_disk_with_a_broken_chain_or_a_downgrade_does_not_open() {
    let d = dir("s4");
    let first = v2(1, &[0u8; 32], 3, 100);
    {
        let mut s = FileStore::open(&d).unwrap();
        filled(&mut s, 5);
        s.put_checkpoint_v2(&first).unwrap();
    }
    let good = std::fs::read_to_string(d.join("checkpoints.log")).unwrap();
    // a v1 line after the v2 line
    let down = format!("{good}{}\n", serde_json::to_string(&v1(5, 300)).unwrap());
    std::fs::write(d.join("checkpoints.log"), &down).unwrap();
    assert!(FileStore::open_read_only(&d).is_err(), "downgrade");
    // a second v2 line that skips the counter
    let skip = v2(3, &first.chain_digest(), 5, 200);
    std::fs::write(
        d.join("checkpoints.log"),
        format!("{good}{}\n", serde_json::to_string(&skip).unwrap()),
    )
    .unwrap();
    assert!(FileStore::open_read_only(&d).is_err(), "broken counter");
    std::fs::write(d.join("checkpoints.log"), &good).unwrap();
    assert!(FileStore::open_read_only(&d).is_ok());
}
#[test]
fn s5_the_memory_store_keeps_v2_checkpoints_too() {
    let mut s = MemoryStore::default();
    filled(&mut s, 4);
    let first = v2(1, &[0u8; 32], 4, 10);
    s.put_checkpoint_v2(&first).unwrap();
    assert_eq!(s.any_checkpoints(), vec![AnyCheckpoint::V2(first)]);
    assert!(s.put_checkpoint(&v1(4, 11)).is_err());
}
