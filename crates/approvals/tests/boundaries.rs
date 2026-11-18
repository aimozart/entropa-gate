//! S3c: tests that pin the boundaries the first mutation run showed were untested.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::*;
use entropa_core::Probe;
use serde_json::Value;

#[test]
fn error_messages_display_their_text() {
    assert_eq!(
        ApprovalError::Invalid("ts: out of range".into()).to_string(),
        "ts: out of range"
    );
    assert_eq!(ApprovalError::NotImplemented.to_string(), NOT_IMPLEMENTED);
}

#[test]
fn key_id_of_nothing_is_nothing() {
    assert_eq!(key_id(""), "");
    assert_eq!(key_id("zz"), "");
}

#[test]
fn ts_accepts_2_pow_53_minus_1_and_rejects_2_pow_53() {
    let f = fx();
    let ok = Event::request(
        &f.requester_id,
        (1 << 53) - 1,
        ActionClass::Delete,
        &subject("s"),
        "stage:S3",
        86_400,
    );
    assert!(sign(&f.requester, &ok).is_ok());
    let too_big = Event::request(
        &f.requester_id,
        1 << 53,
        ActionClass::Delete,
        &subject("s"),
        "stage:S3",
        86_400,
    );
    assert!(matches!(
        sign(&f.requester, &too_big),
        Err(ApprovalError::Invalid(_))
    ));
    let mut v: Value = serde_json::from_str(&must(encode(&sign(&f.requester, &ok).unwrap()))).unwrap();
    v["ts"] = serde_json::json!(1u64 << 53);
    assert!(decode(&v.to_string()).is_err());
}

#[test]
fn optional_hashes_are_validated_when_signing() {
    let f = fx();
    let rid = subject("rid");
    for bad in ["XYZ", &"A".repeat(16), &"a".repeat(15)] {
        assert!(
            matches!(
                sign(
                    &f.owner,
                    &Event::approve(&f.owner_id, NOW, &rid, Some(bad), None)
                ),
                Err(ApprovalError::Invalid(_))
            ),
            "on_behalf_of {bad}"
        );
    }
    for bad in ["not-hex", &"a".repeat(63), &"A".repeat(64)] {
        assert!(
            matches!(
                sign(
                    &f.owner,
                    &Event::approve(&f.owner_id, NOW, &rid, None, Some(bad))
                ),
                Err(ApprovalError::Invalid(_))
            ),
            "basis_hash {bad}"
        );
    }
}

#[test]
fn signature_text_must_be_lowercase_even_length_hex_within_the_limit() {
    let f = fx();
    let good = must(encode(&f.request(ActionClass::Delete, "s", NOW, 86_400)));
    let base: Value = serde_json::from_str(&good).unwrap();
    let sig = base["sig"].as_str().unwrap().to_string();
    for (what, bad) in [
        ("empty", String::new()),
        ("odd length", sig[..sig.len() - 1].to_string()),
        ("uppercase", sig.to_uppercase()),
        ("too long", "ab".repeat(3310)),
        ("not hex", "zz".repeat(10)),
    ] {
        let mut v = base.clone();
        v["sig"] = serde_json::json!(bad);
        assert!(
            matches!(decode(&v.to_string()), Err(ApprovalError::Invalid(_))),
            "sig {what}"
        );
    }
}

#[test]
fn clock_skew_boundary_is_five_minutes() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", NOW - 1000, 86_400);
    let rid = req.event.request_id.clone();
    let just_ok = f.approve_by(&f.owner, &f.owner_id, &rid, NOW + 300);
    assert_eq!(
        replay(&log_with(&[req.clone(), just_ok]), &f.dir, NOW).rejected,
        vec![]
    );
    let too_far = f.approve_by(&f.owner, &f.owner_id, &rid, NOW + 301);
    assert_eq!(
        replay(&log_with(&[req, too_far]), &f.dir, NOW).rejected,
        vec![Rejected {
            index: 1,
            reason: RejectReason::FutureTimestamp
        }]
    );
}

#[test]
fn expiry_boundaries_are_inclusive_for_decisions_and_for_the_gate() {
    let f = fx();
    let req = f.request(ActionClass::Spend, "s1", NOW - 1000, 600);
    let rid = req.event.request_id.clone();
    let expiry = NOW - 1000 + 600;
    let at_expiry = f.approve_by(&f.owner, &f.owner_id, &rid, expiry);
    let state = replay(&log_with(&[req.clone(), at_expiry]), &f.dir, NOW);
    assert_eq!(
        state.rejected,
        vec![],
        "a decision exactly at expiry is accepted"
    );
    assert!(
        matches!(
            check(
                &state,
                ActionClass::Spend,
                &subject("s1"),
                expiry,
                &policy_default()
            ),
            GateDecision::Allowed { .. }
        ),
        "the gate is open exactly at expiry"
    );
    assert_eq!(
        check(
            &state,
            ActionClass::Spend,
            &subject("s1"),
            expiry + 1,
            &policy_default()
        ),
        GateDecision::Blocked(BlockReason::Expired)
    );
    let late = f.approve_by(&f.owner, &f.owner_id, &rid, expiry + 1);
    assert_eq!(
        replay(&log_with(&[req, late]), &f.dir, NOW).rejected,
        vec![Rejected {
            index: 1,
            reason: RejectReason::Expired
        }]
    );
}

#[test]
fn an_attestation_on_behalf_of_the_requester_is_self_approval() {
    let f = fx();
    // a human with a key requests; the reviewer may attest for that same human
    let human = Probe::spawn();
    let mut dir = f.dir.clone();
    let human_id = dir.add(Actor {
        pubkey_hex: human.pubkey_hex(),
        role: Role::Human,
        may_approve: ActionClass::ALL.to_vec(),
        may_attest_for: vec![],
        revoked_at: None,
    });
    dir.actors
        .get_mut(&f.reviewer_id)
        .unwrap()
        .may_attest_for
        .push(human_id.clone());
    let req = must(sign(
        &human,
        &Event::request(
            &human_id,
            NOW - 1000,
            ActionClass::Direction,
            &subject("s1"),
            "stage:S3",
            86_400,
        ),
    ));
    let basis = subject("chat-ref");
    let att = must(sign(
        &f.reviewer,
        &Event::approve(
            &f.reviewer_id,
            NOW - 500,
            &req.event.request_id,
            Some(&human_id),
            Some(&basis),
        ),
    ));
    let state = replay(&log_with(&[req, att]), &dir, NOW);
    assert_eq!(
        state.rejected,
        vec![Rejected {
            index: 1,
            reason: RejectReason::SelfApproval
        }]
    );
}

#[test]
fn a_denial_by_attestation_is_recorded_and_blocks() {
    let f = fx();
    let req = f.request(ActionClass::Direction, "s1", NOW - 1000, 86_400);
    let basis = subject("chat-ref");
    let deny = must(sign(
        &f.reviewer,
        &Event::deny(
            &f.reviewer_id,
            NOW - 500,
            &req.event.request_id,
            ReasonCode::WrongSubject,
            Some(&f.principal_id),
            Some(&basis),
        ),
    ));
    let state = replay(&log_with(&[req, deny]), &f.dir, NOW);
    assert_eq!(state.rejected, vec![]);
    assert_eq!(
        check(
            &state,
            ActionClass::Direction,
            &subject("s1"),
            NOW,
            &policy_default()
        ),
        GateDecision::Blocked(BlockReason::Denied)
    );
}

#[test]
fn a_request_with_a_chosen_id_or_a_duplicate_is_malformed() {
    let f = fx();
    let honest = f.request(ActionClass::Delete, "s1", NOW - 1000, 86_400);
    // an id the requester chose instead of the derived one
    let mut chosen = Event::request(
        &f.requester_id,
        NOW - 900,
        ActionClass::Delete,
        &subject("s1"),
        "stage:S3",
        86_400,
    );
    chosen.request_id = subject("my-own-id");
    let chosen = must(sign(&f.requester, &chosen));
    let state = replay(&log_with(&[honest.clone(), chosen]), &f.dir, NOW);
    assert_eq!(
        state.rejected,
        vec![Rejected {
            index: 1,
            reason: RejectReason::Malformed
        }]
    );
    // the same request recorded twice
    let state = replay(&log_with(&[honest.clone(), honest]), &f.dir, NOW);
    assert_eq!(
        state.rejected,
        vec![Rejected {
            index: 1,
            reason: RejectReason::Malformed
        }]
    );
}
