//! Test-plan rows R1-R12 (docs/ARCHITECTURE-APPROVALS.md section 10).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::BlockReason::*;
use entropa_approvals::*;

const REQ_TS: u64 = NOW - 1000;
const DEC_TS: u64 = NOW - 500;

fn reasons(s: &State) -> Vec<(usize, RejectReason)> {
    s.rejected.iter().map(|r| (r.index, r.reason)).collect()
}

fn gate(state: &State, class: ActionClass, word: &str) -> GateDecision {
    check(state, class, &subject(word), NOW, &policy_default())
}

#[test]
fn r1_request_then_approve_by_an_allowed_human_opens_the_gate() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", REQ_TS, 86_400);
    let a = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, DEC_TS);
    let state = replay(&log_with(&[req.clone(), a]), &f.dir, NOW);
    assert_eq!(state.rejected, vec![]);
    assert_eq!(
        gate(&state, ActionClass::Delete, "s1"),
        GateDecision::Allowed {
            request_id: req.event.request_id,
            approver: f.owner_id.clone(),
            attested: false
        }
    );
}

#[test]
fn r2_a_denial_blocks() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", REQ_TS, 86_400);
    let d = f.deny_by(&f.owner, &f.owner_id, &req.event.request_id, DEC_TS);
    let state = replay(&log_with(&[req, d]), &f.dir, NOW);
    assert_eq!(
        gate(&state, ActionClass::Delete, "s1"),
        GateDecision::Blocked(Denied)
    );
}

#[test]
fn r3_pending_and_no_request() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", REQ_TS, 86_400);
    let state = replay(&log_with(&[req]), &f.dir, NOW);
    assert_eq!(
        gate(&state, ActionClass::Delete, "s1"),
        GateDecision::Blocked(Pending)
    );
    let empty = replay(&log_with(&[]), &f.dir, NOW);
    assert_eq!(
        gate(&empty, ActionClass::Delete, "s1"),
        GateDecision::Blocked(NoRequest)
    );
}

#[test]
fn r4_an_approval_expires_on_the_gate_clock_and_a_late_decision_is_rejected() {
    let f = fx();
    let req = f.request(ActionClass::Spend, "s1", REQ_TS, 60);
    let on_time = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, REQ_TS + 30);
    let state = replay(&log_with(&[req.clone(), on_time]), &f.dir, NOW);
    assert_eq!(
        gate(&state, ActionClass::Spend, "s1"),
        GateDecision::Blocked(Expired)
    );
    let late = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, REQ_TS + 61);
    let state = replay(&log_with(&[req, late]), &f.dir, NOW);
    assert_eq!(reasons(&state), vec![(1, RejectReason::Expired)]);
}

#[test]
fn r5_self_approval_unauthorised_approvers_and_ai_approvers_are_rejected() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", REQ_TS, 86_400);
    let rid = req.event.request_id.clone();
    let self_approval = f.approve_by(&f.requester, &f.requester_id, &rid, DEC_TS);
    let service = f.approve_by(&f.svc, &f.svc_id, &rid, DEC_TS);
    let ai = f.approve_by(&f.reviewer, &f.reviewer_id, &rid, DEC_TS);
    let state = replay(&log_with(&[req, self_approval, service, ai]), &f.dir, NOW);
    assert_eq!(
        reasons(&state),
        vec![
            (1, RejectReason::NotAllowedApprover),
            (2, RejectReason::NotAllowedApprover),
            (3, RejectReason::NotAllowedApprover)
        ]
    );
    assert_eq!(
        gate(&state, ActionClass::Delete, "s1"),
        GateDecision::Blocked(Pending)
    );
}

#[test]
fn r5b_the_requester_cannot_approve_even_when_allowed_to_approve() {
    let f = fx();
    // owner both requests and approves
    let req = must(sign(
        &f.owner,
        &Event::request(
            &f.owner_id,
            REQ_TS,
            ActionClass::Deploy,
            &subject("s1"),
            "stage:S3",
            86_400,
        ),
    ));
    let a = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, DEC_TS);
    let state = replay(&log_with(&[req, a]), &f.dir, NOW);
    assert_eq!(reasons(&state), vec![(1, RejectReason::SelfApproval)]);
}

#[test]
fn r6_bad_signatures_unknown_and_revoked_keys() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", REQ_TS, 86_400);
    let rid = req.event.request_id.clone();
    // signature taken from another event
    let mut forged = f.approve_by(&f.owner, &f.owner_id, &rid, DEC_TS);
    forged.sig = f.approve_by(&f.owner, &f.owner_id, &rid, DEC_TS + 1).sig;
    // a key that is not in the directory
    let stranger = entropa_core::Probe::spawn();
    let stranger_id = key_id(&stranger.pubkey_hex());
    let unknown = must(sign(
        &stranger,
        &Event::approve(&stranger_id, DEC_TS, &rid, None, None),
    ));
    let state = replay(&log_with(&[req.clone(), forged, unknown]), &f.dir, NOW);
    assert_eq!(
        reasons(&state),
        vec![
            (1, RejectReason::BadSignature),
            (2, RejectReason::UnknownActor)
        ]
    );

    // revoked at index 1: an approval recorded at index 1 is rejected, one at index 0.. stays valid
    let ok = f.approve_by(&f.owner, &f.owner_id, &rid, DEC_TS);
    let mut dir = f.dir.clone();
    dir.revoke(&f.owner_id, 1);
    assert_eq!(
        reasons(&replay(&log_with(&[req.clone(), ok.clone()]), &dir, NOW)),
        vec![(1, RejectReason::RevokedKey)]
    );
    let mut dir_later = f.dir.clone();
    dir_later.revoke(&f.owner_id, 2);
    assert_eq!(
        reasons(&replay(&log_with(&[req, ok]), &dir_later, NOW)),
        vec![]
    );
}

#[test]
fn r7_a_decision_before_its_request_is_rejected() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", REQ_TS, 86_400);
    let a = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, DEC_TS);
    let state = replay(&log_with(&[a, req]), &f.dir, NOW);
    assert_eq!(reasons(&state), vec![(0, RejectReason::NoSuchRequest)]);
    assert_eq!(
        gate(&state, ActionClass::Delete, "s1"),
        GateDecision::Blocked(Pending)
    );
}

#[test]
fn r8_the_first_valid_decision_is_final() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", REQ_TS, 86_400);
    let rid = req.event.request_id.clone();
    let a = f.approve_by(&f.owner, &f.owner_id, &rid, DEC_TS);
    let d = f.deny_by(&f.owner, &f.owner_id, &rid, DEC_TS + 1);
    let approve_first = replay(&log_with(&[req.clone(), a.clone(), d.clone()]), &f.dir, NOW);
    assert_eq!(reasons(&approve_first), vec![(2, RejectReason::Superseded)]);
    assert!(matches!(
        gate(&approve_first, ActionClass::Delete, "s1"),
        GateDecision::Allowed { .. }
    ));
    let deny_first = replay(&log_with(&[req, d, a]), &f.dir, NOW);
    assert_eq!(reasons(&deny_first), vec![(2, RejectReason::Superseded)]);
    assert_eq!(
        gate(&deny_first, ActionClass::Delete, "s1"),
        GateDecision::Blocked(Denied)
    );
}

#[test]
fn r9_approving_one_subject_does_not_open_the_gate_for_another() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "subject-A", REQ_TS, 86_400);
    let a = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, DEC_TS);
    let state = replay(&log_with(&[req, a]), &f.dir, NOW);
    assert_eq!(
        gate(&state, ActionClass::Delete, "subject-B"),
        GateDecision::Blocked(SubjectMismatch)
    );
    // and a different class is simply not requested
    assert_eq!(
        gate(&state, ActionClass::Publish, "subject-A"),
        GateDecision::Blocked(NoRequest)
    );
}

#[test]
fn r10_an_approval_is_single_use() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", REQ_TS, 86_400);
    let rid = req.event.request_id.clone();
    let a = f.approve_by(&f.owner, &f.owner_id, &rid, DEC_TS);
    let used = f.consume_by_requester(&rid, DEC_TS + 10);
    let used_again = f.consume_by_requester(&rid, DEC_TS + 20);
    let state = replay(
        &log_with(&[req.clone(), a.clone(), used.clone(), used_again]),
        &f.dir,
        NOW,
    );
    assert_eq!(
        gate(&state, ActionClass::Delete, "s1"),
        GateDecision::Blocked(AlreadyUsed)
    );
    assert_eq!(reasons(&state), vec![(3, RejectReason::BadConsume)]);
    // consume without an approval is rejected too
    let state = replay(&log_with(&[req, used]), &f.dir, NOW);
    assert_eq!(reasons(&state), vec![(1, RejectReason::BadConsume)]);
}

/// the reviewer's override: an attestation never opens the gate for the hard-rule classes.
#[test]
fn r11_attestation_allows_direction_only_and_never_the_hard_rule_classes() {
    let f = fx();
    for (class, allowed) in [
        (ActionClass::Direction, true),
        (ActionClass::Delete, false),
        (ActionClass::Spend, false),
        (ActionClass::Publish, false),
        (ActionClass::CredentialsChange, false),
    ] {
        let req = f.request(class, "s1", REQ_TS, 86_400);
        let a = f.attest_approve(&req.event.request_id, DEC_TS);
        let state = replay(&log_with(&[req, a]), &f.dir, NOW);
        assert_eq!(
            state.rejected,
            vec![],
            "{class:?}: the attested event is still recorded, not rejected"
        );
        for policy in [policy_default(), policy_all()] {
            let got = check(&state, class, &subject("s1"), NOW, &policy);
            if allowed {
                assert!(
                    matches!(&got, GateDecision::Allowed { attested: true, approver, .. } if *approver == f.reviewer_id),
                    "{class:?}: {got:?}"
                );
            } else {
                assert_eq!(
                    got,
                    GateDecision::Blocked(AttestationNotAccepted),
                    "{class:?} with policy {policy:?}"
                );
            }
        }
    }
}

#[test]
fn r11b_only_listed_attestors_may_attest() {
    let f = fx();
    let req = f.request(ActionClass::Direction, "s1", REQ_TS, 86_400);
    let basis = subject("chat-ref");
    // requester is not allowed to attest for the principal
    let bad = must(sign(
        &f.requester,
        &Event::approve(
            &f.requester_id,
            DEC_TS,
            &req.event.request_id,
            Some(&f.principal_id),
            Some(&basis),
        ),
    ));
    let state = replay(&log_with(&[req, bad]), &f.dir, NOW);
    assert_eq!(
        reasons(&state),
        vec![(1, RejectReason::AttestationNotPermitted)]
    );
}

#[test]
fn r12_a_timestamp_ten_minutes_in_the_future_is_rejected() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", REQ_TS, 86_400);
    let a = f.approve_by(&f.owner, &f.owner_id, &req.event.request_id, NOW + 600);
    let state = replay(&log_with(&[req, a]), &f.dir, NOW);
    assert_eq!(reasons(&state), vec![(1, RejectReason::FutureTimestamp)]);
}
