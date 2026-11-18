//! Test-plan rows L1-L3 and P1: the log round trip and the gate invariant.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::*;
use entropa_core::transparency_log::{decode_record, verify_receipt};
use entropa_core::Probe;
use proptest::prelude::*;

#[test]
fn l1_events_in_a_real_log_replay_and_every_receipt_verifies() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", NOW - 1000, 86_400);
    let a = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, NOW - 500);
    let events = vec![req, a];
    let log = log_with(&events);
    let probe = Probe::spawn();
    let head = log.checkpoint(&probe, NOW);
    for (i, e) in events.iter().enumerate() {
        let receipt = log.receipt(i, &head).unwrap();
        assert!(verify_receipt(&receipt, &probe.pubkey_hex()));
        let (payload, label) = decode_record(&receipt.record).unwrap();
        assert_eq!(
            label.as_deref(),
            Some(
                format!(
                    "approval.{}",
                    match &e.event.body {
                        Body::Request { .. } => "request",
                        Body::Approve { .. } => "approve",
                        Body::Deny { .. } => "deny",
                        Body::Consume => "consume",
                    }
                )
                .as_str()
            )
        );
        assert_eq!(&must(decode(&payload)), e);
    }
    assert_eq!(replay(&log, &f.dir, NOW).rejected, vec![]);
}

#[test]
fn l2_replay_is_deterministic_and_unaffected_by_checkpoints() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", NOW - 1000, 86_400);
    let a = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, NOW - 500);
    let log = log_with(&[req, a]);
    let before = replay(&log, &f.dir, NOW);
    let _ = log.checkpoint(&Probe::spawn(), NOW);
    assert_eq!(before, replay(&log, &f.dir, NOW));
    assert!(
        matches!(
            check(
                &before,
                ActionClass::Delete,
                &subject("s1"),
                NOW,
                &policy_default()
            ),
            GateDecision::Allowed { .. }
        ),
        "gate: {NOT_IMPLEMENTED}"
    );
}

#[test]
fn l3_other_records_in_the_same_log_are_ignored_not_rejected() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", NOW - 1000, 86_400);
    let a = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, NOW - 500);
    let mut log = log_with(&[req]);
    note_record(&mut log);
    must(append_event(&mut log, &a));
    let state = replay(&log, &f.dir, NOW);
    assert_eq!(state.rejected, vec![]);
    assert!(matches!(
        check(
            &state,
            ActionClass::Delete,
            &subject("s1"),
            NOW,
            &policy_default()
        ),
        GateDecision::Allowed { .. }
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    /// P1: whatever sequence of events is recorded, the gate only opens through a valid human
    /// approval (owner), or an attestation for the direction class (the reviewer). The author and the service
    /// never open it, and a hard-rule class is never opened by an attestation.
    #[test]
    fn p1_the_gate_never_opens_without_a_valid_approver(
        ops in prop::collection::vec((0usize..4, 0usize..4, 0usize..8, 0u64..5_000), 1..14)
    ) {
        let f = fx();
        let signers: [(&Probe, &str); 4] = [(&f.owner, &f.owner_id), (&f.reviewer, &f.reviewer_id), (&f.requester, &f.requester_id), (&f.svc, &f.svc_id)];
        let mut events: Vec<SignedEvent> = Vec::new();
        let mut known: Vec<String> = Vec::new();
        for (actor, op, class_i, dt) in ops {
            let (probe, id) = signers[actor];
            let class = ActionClass::ALL[class_i];
            let ts = NOW - 5_000 + dt;
            let ev = match op {
                0 => { let e = must(sign(probe, &Event::request(id, ts, class, &subject("s"), "stage:S3", 86_400))); known.push(e.event.request_id.clone()); e }
                1 | 2 if !known.is_empty() => {
                    let rid = &known[(dt as usize) % known.len()];
                    let behalf = if actor == 1 { Some(f.principal_id.as_str()) } else { None };
                    let basis = subject("chat-ref");
                    let event = if op == 1 { Event::approve(id, ts, rid, behalf, Some(&basis)) } else { Event::deny(id, ts, rid, ReasonCode::Other, behalf, Some(&basis)) };
                    must(sign(probe, &event))
                }
                _ => continue,
            };
            events.push(ev);
        }
        let state = replay(&log_with(&events), &f.dir, NOW);
        for class in ActionClass::ALL {
            if let GateDecision::Allowed { approver, attested, .. } = check(&state, class, &subject("s"), NOW, &policy_all()) {
                prop_assert!(approver != f.requester_id && approver != f.svc_id);
                if attested {
                    prop_assert!(class == ActionClass::Direction);
                    prop_assert_eq!(approver, f.reviewer_id.clone());
                } else {
                    prop_assert_eq!(approver, f.owner_id.clone());
                }
            }
        }
    }
}
