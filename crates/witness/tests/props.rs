//! Test-plan row W11: random append histories. The witness accepts exactly the extensions that
//! carry a valid consistency proof, and the statements chain.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_witness::*;
use proptest::prelude::*;

fn sizes() -> impl Strategy<Value = Vec<usize>> {
    // strictly increasing sizes between 1 and 60, one to six checkpoints
    prop::collection::vec(1usize..8, 1..7).prop_map(|steps| {
        let mut acc = 0;
        steps
            .into_iter()
            .map(|s| {
                acc += s;
                acc
            })
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn w11_valid_histories_are_accepted_and_the_statements_chain(sz in sizes()) {
        let log = log_with(*sz.last().unwrap());
        let (w, store) = witness(&log, true);
        let mut prev: Option<(usize, String)> = None;
        for (i, &n) in sz.iter().enumerate() {
            let cp = log.checkpoint(n, TS + i as u64);
            let proof = prev.as_ref().map_or(Vec::new(), |(p, _)| log.proof(*p, n));
            let st = cosign_ok(&w, &body(&log.log_id(), &cp, &proof), NOW + i as u64);
            match &prev {
                None => prop_assert_eq!((st.fields.previous_size, st.fields.previous_root.as_str()), (0, NO_PREVIOUS_ROOT)),
                Some((p, r)) => { prop_assert_eq!(st.fields.previous_size, *p as u64); prop_assert_eq!(&st.fields.previous_root, r); }
            }
            prop_assert_eq!(st.fields.size, n as u64);
            prev = Some((n, hex::encode(cp.root)));
            prop_assert_eq!(store.state(&log.log_id()).unwrap().size, n);
        }
    }

    #[test]
    fn w11_a_corrupted_proof_is_always_refused_and_the_state_never_moves(sz in sizes(), which in 0usize..8, bit in 0u8..8, kind in 0u8..3) {
        prop_assume!(sz.len() >= 2);
        let log = log_with(*sz.last().unwrap());
        let (w, store) = witness(&log, true);
        let first = log.checkpoint(sz[0], TS);
        cosign_ok(&w, &body(&log.log_id(), &first, &[]), NOW);
        let n = sz[1];
        let mut proof = log.proof(sz[0], n);
        prop_assume!(!proof.is_empty());
        match kind {
            0 => { let k = which % proof.len(); proof[k][bit as usize] ^= 1 << bit; }
            1 => { proof.pop(); }
            _ => { proof.push([bit; 32]); }
        }
        let cp = log.checkpoint(n, TS + 1);
        prop_assert_eq!(cosign_err(&w, &body(&log.log_id(), &cp, &proof), NOW), WitnessError::BadConsistency);
        prop_assert_eq!(store.state(&log.log_id()).unwrap().size, sz[0]);
    }
}
