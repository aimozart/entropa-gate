//! Property tests (proptest): Merkle proofs and receipts hold for any log size and index.
//! Seeds: proptest persists failing cases under `proptest-regressions/`; commit those files.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_core::merkle::{
    consistency_proof, inclusion_proof, leaf_hash, root, verify_consistency, verify_inclusion,
};
use entropa_core::transparency_log::{verify_receipt, TransparencyLog};
use entropa_core::Probe;
use proptest::prelude::*;

fn records() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..32), 1..80)
}

proptest! {
    #[test]
    fn every_leaf_has_a_valid_inclusion_proof_and_a_tampered_one_fails(recs in records(), pick in any::<prop::sample::Index>()) {
        let leaves: Vec<_> = recs.iter().map(|r| leaf_hash(r)).collect();
        let r = root(&leaves).unwrap();
        let i = pick.index(leaves.len());
        let proof = inclusion_proof(&leaves, i).unwrap();
        prop_assert!(verify_inclusion(&leaves[i], &proof, &r));
        // a different leaf must not verify under the same proof
        let other = leaf_hash(b"\xffnot-a-record\xff");
        prop_assert!(!verify_inclusion(&other, &proof, &r));
        // flipping one bit of any sibling must fail
        if !proof.is_empty() {
            let mut bad = proof.clone();
            let k = pick.index(bad.len());
            bad[k].sibling[0] ^= 1;
            prop_assert!(!verify_inclusion(&leaves[i], &bad, &r));
        }
    }

    #[test]
    fn out_of_range_indices_have_no_proof(recs in records(), extra in 0usize..5) {
        let leaves: Vec<_> = recs.iter().map(|r| leaf_hash(r)).collect();
        prop_assert!(inclusion_proof(&leaves, leaves.len() + extra).is_none());
    }

    #[test]
    fn consistency_proofs_verify_for_every_prefix(recs in records(), pick in any::<prop::sample::Index>()) {
        let leaves: Vec<_> = recs.iter().map(|r| leaf_hash(r)).collect();
        let old = 1 + pick.index(leaves.len());
        let proof = consistency_proof(&leaves, old).unwrap();
        let old_root = root(&leaves[..old]).unwrap();
        let new_root = root(&leaves).unwrap();
        prop_assert!(verify_consistency(&old_root, old, &new_root, leaves.len(), &proof));
        // a forged old root must fail
        let mut forged = old_root;
        forged[0] ^= 1;
        prop_assert!(!verify_consistency(&forged, old, &new_root, leaves.len(), &proof));
    }

    #[test]
    fn incremental_root_equals_full_rebuild(recs in records()) {
        let mut log = TransparencyLog::new();
        for r in &recs { log.append(r); }
        let leaves: Vec<_> = recs.iter().map(|r| leaf_hash(r)).collect();
        prop_assert_eq!(log.root(), root(&leaves));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn signed_receipts_verify_for_any_record_and_fail_under_another_key(recs in records(), pick in any::<prop::sample::Index>(), ts in any::<u64>()) {
        let signer = Probe::spawn();
        let mut log = TransparencyLog::new();
        for r in &recs { log.append(r); }
        let cp = log.checkpoint(&signer, ts);
        let i = pick.index(recs.len());
        let receipt = log.receipt(i, &cp).unwrap();
        prop_assert_eq!(&receipt.record, &recs[i]);
        prop_assert!(verify_receipt(&receipt, &signer.pubkey_hex()));
        prop_assert!(!verify_receipt(&receipt, &Probe::spawn().pubkey_hex()));
        // JSON round-trip keeps it verifiable
        let json = serde_json::to_string(&receipt).unwrap();
        let back = serde_json::from_str(&json).unwrap();
        prop_assert!(verify_receipt(&back, &signer.pubkey_hex()));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    /// S0g: a receipt only verifies at its own index; any other claimed index fails.
    #[test]
    fn a_receipt_verifies_only_at_its_own_index(recs in records(), pick in any::<prop::sample::Index>(), other in any::<prop::sample::Index>()) {
        let signer = Probe::spawn();
        let mut log = TransparencyLog::new();
        for r in &recs { log.append(r); }
        let cp = log.checkpoint(&signer, 1);
        let i = pick.index(recs.len());
        let mut receipt = log.receipt(i, &cp).unwrap();
        prop_assert!(verify_receipt(&receipt, &signer.pubkey_hex()));
        let j = other.index(recs.len() + 3);
        if j != i {
            receipt.index = j;
            prop_assert!(!verify_receipt(&receipt, &signer.pubkey_hex()));
        }
    }
}
