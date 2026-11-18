//! LEDGER-INCREMENTAL L1 at size: 3,000 appends by two interleaved writers (random order, fixed seed); the unchanged verifier accepts the ledger and the last checkpoint root equals an independent
//! Merkle root of the stored records. Also a checkpoint at EVERY size is checked by the verifier's own load (it re-derives each root).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::merkle::{leaf_hash, root};
use entropa_core::Probe;
use entropa_ledger::{
    evidence_fields, ControlCode, Decision, EvidenceRecord, FileStore, Kind, LabelCode,
    LedgerStore, ReasonCode,
};
use entropa_tiers::append::IncrementalLedger;

#[test]
fn l1_at_size_two_interleaved_writers_3000_records_verify_and_roots_match_an_independent_computation(
) {
    let d = std::env::temp_dir().join(format!("inc-big-{}", std::process::id()));
    std::fs::create_dir_all(d.join("evidence-ledger")).unwrap();
    let probe =
        || Probe::from_signing_key_hex(&hex::encode(blake3::hash(b"inc-big").as_bytes())).unwrap();
    let kid = entropa_approvals::key_id(&probe().pubkey_hex());
    let (a, b) = (
        IncrementalLedger::new(d.clone(), Box::new(probe())),
        IncrementalLedger::new(d.clone(), Box::new(probe())),
    );
    let mut x = 20261215u64;
    for i in 0..3000u64 {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let w = if (x >> 33).is_multiple_of(2) { &a } else { &b };
        let detail = format!("d{i}");
        let run = format!("{i:064x}");
        let f = evidence_fields(&EvidenceRecord {
            kind: Kind::parse("evidence.policy").unwrap(),
            label: LabelCode::parse("policy_verdict").unwrap(),
            decision: Decision::Allow,
            reason: ReasonCode::parse("within_limits").unwrap(),
            control: ControlCode::parse("hitrust_01_access_control").unwrap(),
            total: 1,
            passed: 1,
            flagged: 0,
            detail: &detail,
            run_id: &run,
            ts: 1_800_000_000 + i,
            key_id: kid.clone(),
        })
        .unwrap();
        assert_eq!(w.append_event(&f).unwrap(), i as usize);
    }
    let out = entropa_platinum::verify_evidence_with(&d, &probe().pubkey_hex()).unwrap();
    assert!(out.contains("records=3000 checkpoints=3000"), "{out}");
    let store = FileStore::open(&d.join("evidence-ledger")).unwrap();
    let leaves: Vec<_> = (0..store.len())
        .map(|i| leaf_hash(&store.record(i).unwrap()))
        .collect();
    for cp in store.checkpoints().iter().step_by(97) {
        assert_eq!(
            root(&leaves[..cp.size]).unwrap(),
            cp.root,
            "checkpoint of size {}",
            cp.size
        );
    }
    assert_eq!(
        store.checkpoints().last().unwrap().root,
        root(&leaves).unwrap()
    );
}
