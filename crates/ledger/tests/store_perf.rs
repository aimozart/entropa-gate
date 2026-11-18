//! LEDGER-STORE-VERIFY performance bars (release; run with `--ignored`): a file ledger with a checkpoint per record. Checkpoints are built from `entropa_core::TransparencyLog` roots (the store does not
//! check signatures), so the test measures the store, not the signer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::transparency_log::{Checkpoint, TransparencyLog};
use entropa_ledger::{FileStore, LedgerStore};
use std::time::Instant;

#[test]
#[ignore]
fn p1_open_of_6000_records_with_a_checkpoint_each_is_fast_and_put_checkpoint_does_not_grow() {
    let d = std::env::temp_dir().join(format!("lsv-perf-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let mut log = TransparencyLog::new();
    let mut s = FileStore::open(&d).unwrap();
    let mut put_us = Vec::new();
    for i in 0..6000usize {
        let rec = format!("rec-{i}").into_bytes();
        s.append(&rec).unwrap();
        log.append(&rec);
        let cp = Checkpoint {
            root: log.root().unwrap(),
            size: i + 1,
            timestamp: 1_800_000_000 + i as u64,
            proposer_pubkey: "00".into(),
            signature: "00".into(),
        };
        let t = Instant::now();
        s.put_checkpoint(&cp).unwrap();
        put_us.push(t.elapsed().as_micros() as f64);
    }
    drop(s);
    let first: f64 = put_us[..10].iter().sum::<f64>() / 10.0;
    let last: f64 = put_us[5990..].iter().sum::<f64>() / 10.0;
    let t = Instant::now();
    let s = FileStore::open(&d).unwrap();
    let open = t.elapsed().as_secs_f64();
    assert_eq!((s.len(), s.checkpoints().len()), (6000, 6000));
    eprintln!("open of 6,000 records with 6,000 checkpoints: {open:.3} s; put_checkpoint first 10 avg {first:.1} us, last 10 avg {last:.1} us (ratio {:.1})", last / first.max(1.0));
    assert!(open <= 0.5, "open took {open} s");
    assert!(
        last <= 10.0 * first.max(5.0),
        "put_checkpoint grew from {first} to {last} us"
    );
}
