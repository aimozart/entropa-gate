//! Test-plan rows W1-W7 (docs/ARCHITECTURE-WITNESS.md section 8): the protocol.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use entropa_witness::*;

#[test]
fn w1_first_checkpoint_then_extension_then_the_statements_chain() {
    let log = log_with(10);
    let (w, store) = witness(&log, true);
    let cp3 = log.checkpoint(3, TS);
    let s1 = cosign_ok(&w, &body(&log.log_id(), &cp3, &[]), NOW);
    assert_eq!(s1.fields.log_id, log.log_id());
    assert_eq!(
        (s1.fields.size, s1.fields.root.clone()),
        (3, hex::encode(cp3.root))
    );
    assert_eq!(
        (s1.fields.previous_size, s1.fields.previous_root.as_str()),
        (0, NO_PREVIOUS_ROOT)
    );
    assert_eq!((s1.fields.log_timestamp, s1.fields.witness_time), (TS, NOW));
    assert_eq!(s1.fields.witness_pubkey, w.pubkey_hex());
    assert_eq!(
        store.state(&log.log_id()),
        Some(State {
            size: 3,
            root: cp3.root
        })
    );

    let cp7 = log.checkpoint(7, TS + 10);
    let s2 = cosign_ok(&w, &body(&log.log_id(), &cp7, &log.proof(3, 7)), NOW + 5);
    assert_eq!(
        (s2.fields.previous_size, s2.fields.previous_root.clone()),
        (3, hex::encode(cp3.root))
    );
    assert_eq!((s2.fields.size, s2.fields.witness_time), (7, NOW + 5));
    assert_eq!(
        store.state(&log.log_id()),
        Some(State {
            size: 7,
            root: cp7.root
        })
    );
}

#[test]
fn w1_the_same_checkpoint_again_is_accepted_and_changes_nothing() {
    let log = log_with(8);
    let (w, store) = witness(&log, true);
    let cp = log.checkpoint(8, TS);
    cosign_ok(&w, &body(&log.log_id(), &cp, &[]), NOW);
    let again = cosign_ok(&w, &body(&log.log_id(), &cp, &[]), NOW + 1);
    assert_eq!((again.fields.previous_size, again.fields.size), (8, 8));
    assert_eq!(
        store.state(&log.log_id()),
        Some(State {
            size: 8,
            root: cp.root
        })
    );
    // an unchanged size with a non-empty proof is not valid
    let proof = log.proof(3, 8);
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &cp, &proof), NOW),
        WitnessError::BadConsistency
    );
}

#[test]
fn w1_an_empty_log_can_be_the_first_checkpoint_and_is_extended_with_an_empty_proof() {
    let log = log_with(5);
    let (w, store) = witness(&log, true);
    let cp0 = log.checkpoint(0, TS);
    cosign_ok(&w, &body(&log.log_id(), &cp0, &[]), NOW);
    assert_eq!(store.state(&log.log_id()).unwrap().size, 0);
    let cp3 = log.checkpoint(3, TS + 1);
    // from size 0 no proof exists: a non-empty one is refused, an empty one accepted
    let fake = log.proof(1, 3);
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &cp3, &fake), NOW),
        WitnessError::BadConsistency
    );
    cosign_ok(&w, &body(&log.log_id(), &cp3, &[]), NOW);
    assert_eq!(store.state(&log.log_id()).unwrap().size, 3);
}

#[test]
fn w1_the_first_checkpoint_is_refused_unless_allow_first_is_on() {
    let log = log_with(4);
    let (w, store) = witness(&log, false);
    let cp = log.checkpoint(4, TS);
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &cp, &[]), NOW),
        WitnessError::FirstNotAllowed
    );
    assert_eq!(store.state(&log.log_id()), None);
}

#[test]
fn w1_with_a_seeded_state_allow_first_is_not_needed() {
    let log = log_with(9);
    let (w, store) = witness(&log, false);
    let cp4 = log.checkpoint(4, TS);
    store.put(
        &log.log_id(),
        State {
            size: 4,
            root: cp4.root,
        },
    );
    let cp9 = log.checkpoint(9, TS + 1);
    cosign_ok(&w, &body(&log.log_id(), &cp9, &log.proof(4, 9)), NOW);
    assert_eq!(store.state(&log.log_id()).unwrap().size, 9);
}

#[test]
fn w2_a_smaller_checkpoint_is_a_rollback_and_leaves_the_state_alone() {
    let log = log_with(10);
    let (w, store) = witness(&log, true);
    let cp7 = log.checkpoint(7, TS);
    cosign_ok(&w, &body(&log.log_id(), &cp7, &[]), NOW);
    let cp3 = log.checkpoint(3, TS + 1);
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &cp3, &[]), NOW),
        WitnessError::Rollback
    );
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &cp3, &log.proof(3, 7)), NOW),
        WitnessError::Rollback
    );
    assert_eq!(
        store.state(&log.log_id()),
        Some(State {
            size: 7,
            root: cp7.root
        })
    );
    assert!(
        store.equivocations().is_empty(),
        "a rollback is not equivocation evidence"
    );
}

#[test]
fn w3_the_same_size_with_a_different_root_is_equivocation_and_is_recorded() {
    let log = log_with(10);
    let fork = SynthLog::new(
        Probe::from_signing_key_hex(&log.probe.signing_key_hex()).unwrap(),
        "alt",
        10,
    );
    assert_eq!(
        fork.pubkey(),
        log.pubkey(),
        "the fork is signed by the same log key"
    );
    let (w, store) = witness(&log, true);
    let real5 = log.checkpoint(5, TS);
    cosign_ok(&w, &body(&log.log_id(), &real5, &[]), NOW);
    let forked5 = fork.checkpoint(5, TS + 1);
    assert_ne!(real5.root, forked5.root);
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &forked5, &[]), NOW),
        WitnessError::Equivocation
    );
    assert_eq!(
        store.state(&log.log_id()),
        Some(State {
            size: 5,
            root: real5.root
        })
    );
    let ev = store.equivocations();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, log.log_id());
    assert!(
        ev[0].1.contains(&hex::encode(real5.root)) && ev[0].1.contains(&hex::encode(forked5.root)),
        "both checkpoints are in the evidence"
    );
    // the honest history still works afterwards
    let real9 = log.checkpoint(9, TS + 2);
    cosign_ok(&w, &body(&log.log_id(), &real9, &log.proof(5, 9)), NOW);
}

#[test]
fn w3_a_signed_checkpoint_from_a_forked_history_that_fails_consistency_is_recorded_too() {
    let log = log_with(10);
    let fork = SynthLog::new(
        Probe::from_signing_key_hex(&log.probe.signing_key_hex()).unwrap(),
        "alt",
        10,
    );
    let (w, store) = witness(&log, true);
    cosign_ok(&w, &body(&log.log_id(), &log.checkpoint(5, TS), &[]), NOW);
    let forked9 = fork.checkpoint(9, TS + 1);
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &forked9, &fork.proof(5, 9)), NOW),
        WitnessError::BadConsistency
    );
    assert_eq!(store.equivocations().len(), 1);
    assert_eq!(store.state(&log.log_id()).unwrap().size, 5);
}

#[test]
fn w4_every_broken_proof_is_refused_and_the_state_stays() {
    let log = log_with(12);
    let (w, store) = witness(&log, true);
    let cp3 = log.checkpoint(3, TS);
    cosign_ok(&w, &body(&log.log_id(), &cp3, &[]), NOW);
    let cp7 = log.checkpoint(7, TS + 1);
    let good = log.proof(3, 7);
    assert!(good.len() >= 2);
    let mut flipped = good.clone();
    flipped[0][0] ^= 1;
    let mut extra = good.clone();
    extra.push([7u8; 32]);
    let bad: Vec<(&str, Vec<[u8; 32]>)> = vec![
        ("empty", vec![]),
        ("truncated", good[..good.len() - 1].to_vec()),
        ("extra element", extra),
        ("flipped bit", flipped),
        ("proof for 4 to 7", log.proof(4, 7)),
        ("proof for 3 to 8", log.proof(3, 8)),
        ("reversed", good.iter().rev().cloned().collect()),
    ];
    for (name, proof) in bad {
        let e = cosign_err(&w, &body(&log.log_id(), &cp7, &proof), NOW);
        assert_eq!(e, WitnessError::BadConsistency, "{name}");
        assert_eq!(
            store.state(&log.log_id()),
            Some(State {
                size: 3,
                root: cp3.root
            }),
            "{name}"
        );
    }
    // and the good proof still works afterwards
    cosign_ok(&w, &body(&log.log_id(), &cp7, &good), NOW);
}

#[test]
fn w5_the_log_key_comes_from_configuration_never_from_the_request() {
    let log = log_with(6);
    let attacker = log_with(6);
    let (w, store) = witness(&log, true);
    // a checkpoint signed by another key, under the configured log id
    let cp = attacker.checkpoint(6, TS);
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &cp, &[]), NOW),
        WitnessError::BadSignature
    );
    // the attacker rewrites the claimed key to the configured one but keeps its own signature
    let mut forged = attacker.checkpoint(6, TS);
    forged.proposer_pubkey = log.pubkey();
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &forged, &[]), NOW),
        WitnessError::BadSignature
    );
    // the attacker's own log id is not configured
    let cp2 = attacker.checkpoint(6, TS);
    assert_eq!(
        cosign_err(&w, &body(&attacker.log_id(), &cp2, &[]), NOW),
        WitnessError::UnknownLog
    );
    assert_eq!(store.state(&log.log_id()), None);
}

#[test]
fn w6_a_tampered_checkpoint_fails_the_signature() {
    let log = log_with(6);
    let (w, store) = witness(&log, true);
    let good = log.checkpoint(6, TS);
    let mut a = good.clone();
    a.root[0] ^= 1;
    let mut b = good.clone();
    b.size += 1;
    let mut c = good.clone();
    c.timestamp += 1;
    let mut d = good.clone();
    d.signature.replace_range(
        ..2,
        if good.signature.starts_with("00") {
            "ff"
        } else {
            "00"
        },
    );
    let mut e = good.clone();
    e.signature.truncate(e.signature.len() - 2);
    for (name, cp) in [
        ("root", a),
        ("size", b),
        ("timestamp", c),
        ("signature byte", d),
        ("short signature", e),
    ] {
        let err = cosign_err(&w, &body(&log.log_id(), &cp, &[]), NOW);
        assert!(
            matches!(err, WitnessError::BadSignature | WitnessError::Invalid(_)),
            "{name}: {err:?}"
        );
        assert_eq!(store.state(&log.log_id()), None, "{name}");
    }
}

#[test]
fn w7_an_unknown_log_id_is_refused() {
    let log = log_with(3);
    let (w, _) = witness(&log, true);
    let cp = log.checkpoint(3, TS);
    let other = "ab".repeat(32);
    assert_eq!(
        cosign_err(&w, &body(&other, &cp, &[]), NOW),
        WitnessError::UnknownLog
    );
}

#[test]
fn w7_the_configuration_is_checked_when_the_witness_is_built() {
    let log = log_with(1);
    let other = log_with(1);
    let build = |logs: Vec<LogConfig>| Witness::new(logs, TestStore::new(), Probe::spawn());
    let wrong_id = LogConfig {
        log_id: other.log_id(),
        pubkey_hex: log.pubkey(),
        allow_first: true,
    };
    let dup = vec![config(&log, true), config(&log, false)];
    for (name, cfg) in [
        ("log_id not derived from the key", vec![wrong_id]),
        ("duplicate log id", dup),
    ] {
        match build(cfg) {
            Err(WitnessError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
            Err(WitnessError::Invalid(_)) => {}
            Err(e) => panic!("{name}: wrong error {e:?}"),
            Ok(_) => panic!("{name}: the witness was built"),
        }
    }
    assert!(
        build(vec![config(&log, true), config(&other, true)]).is_ok(),
        "two distinct logs are fine"
    );
}

#[test]
fn w7_the_log_id_is_the_blake3_of_the_raw_public_key() {
    let log = log_with(1);
    let id = log_id_for(&log.pubkey());
    if id.is_empty() {
        panic!("{NOT_IMPLEMENTED}");
    }
    assert_eq!(id, log.log_id());
    assert_eq!(id.len(), 64);
}
