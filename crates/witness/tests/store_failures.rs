//! Test-plan rows W8-W9: a lost race, store failures and signer failures sign nothing and never
//! advance the state (the statement is built first and released only after the swap succeeds).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use entropa_witness::*;

fn seeded(
    n: usize,
) -> (
    SynthLog,
    std::sync::Arc<TestStore>,
    Witness<std::sync::Arc<TestStore>, Probe>,
) {
    let log = log_with(12);
    let (w, store) = witness(&log, true);
    cosign_ok(&w, &body(&log.log_id(), &log.checkpoint(n, TS), &[]), NOW);
    (log, store, w)
}

#[test]
fn w8_the_loser_of_a_compare_and_swap_gets_a_retryable_error_and_no_statement() {
    let (log, store, w) = seeded(3);
    let cp7 = log.checkpoint(7, TS + 1);
    let req = body(&log.log_id(), &cp7, &log.proof(3, 7));
    store.inner.lock().unwrap().conflict_next_cas = true;
    assert_eq!(cosign_err(&w, &req, NOW), WitnessError::StoreConflict);
    assert_eq!(store.state(&log.log_id()).unwrap().size, 3);
    cosign_ok(&w, &req, NOW); // the retry succeeds
    assert_eq!(store.state(&log.log_id()).unwrap().size, 7);
}

#[test]
fn w8_a_writer_that_advanced_the_state_between_read_and_swap_makes_us_lose() {
    let (log, store, w) = seeded(3);
    let cp5 = log.checkpoint(5, TS + 1);
    let root5 = cp5.root;
    let id = log.log_id();
    store.inner.lock().unwrap().before_cas = Some(Box::new(move |states| {
        let v = states.get(&id).map_or(1, |(_, v)| v + 1);
        states.insert(
            id.clone(),
            (
                State {
                    size: 5,
                    root: root5,
                },
                v,
            ),
        );
    }));
    let cp7 = log.checkpoint(7, TS + 2);
    assert_eq!(
        cosign_err(&w, &body(&log.log_id(), &cp7, &log.proof(3, 7)), NOW),
        WitnessError::StoreConflict
    );
    assert_eq!(
        store.state(&log.log_id()).unwrap().size,
        5,
        "the other writer's state is untouched"
    );
}

#[test]
fn w9_a_failing_store_read_signs_nothing() {
    let (log, store, w) = seeded(3);
    store.inner.lock().unwrap().fail_get = true;
    let cp7 = log.checkpoint(7, TS + 1);
    assert!(matches!(
        cosign_err(&w, &body(&log.log_id(), &cp7, &log.proof(3, 7)), NOW),
        WitnessError::Store(_)
    ));
    store.inner.lock().unwrap().fail_get = false;
    assert_eq!(store.state(&log.log_id()).unwrap().size, 3);
}

#[test]
fn w9_a_failing_store_write_signs_nothing_and_does_not_advance() {
    let (log, store, w) = seeded(3);
    store.inner.lock().unwrap().fail_cas = true;
    let cp7 = log.checkpoint(7, TS + 1);
    assert!(matches!(
        cosign_err(&w, &body(&log.log_id(), &cp7, &log.proof(3, 7)), NOW),
        WitnessError::Store(_)
    ));
    assert_eq!(store.state(&log.log_id()).unwrap().size, 3);
}

#[test]
fn w9_a_failing_signer_signs_nothing_and_does_not_advance() {
    let log = log_with(10);
    let store = TestStore::new();
    let w = match Witness::new(
        vec![config(&log, true)],
        store.clone(),
        FailingSigner(Probe::spawn()),
    ) {
        Ok(w) => w,
        Err(WitnessError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => panic!("{e:?}"),
    };
    let cp = log.checkpoint(4, TS);
    assert!(matches!(
        cosign_err(&w, &body(&log.log_id(), &cp, &[]), NOW),
        WitnessError::Sign(_)
    ));
    assert_eq!(
        store.state(&log.log_id()),
        None,
        "the swap must not happen before the signature exists"
    );
    assert_eq!(store.inner.lock().unwrap().cas_calls, 0);
}

#[test]
fn w9_a_failing_evidence_write_still_refuses_and_leaves_the_state() {
    let log = log_with(10);
    let fork = SynthLog::new(
        Probe::from_signing_key_hex(&log.probe.signing_key_hex()).unwrap(),
        "alt",
        10,
    );
    let (w, store) = witness(&log, true);
    cosign_ok(&w, &body(&log.log_id(), &log.checkpoint(5, TS), &[]), NOW);
    store.inner.lock().unwrap().fail_equivocation = true;
    let e = cosign_err(
        &w,
        &body(&log.log_id(), &fork.checkpoint(5, TS + 1), &[]),
        NOW,
    );
    assert!(
        matches!(e, WitnessError::Equivocation | WitnessError::Store(_)),
        "{e:?}"
    );
    assert_eq!(store.state(&log.log_id()).unwrap().size, 5);
}
