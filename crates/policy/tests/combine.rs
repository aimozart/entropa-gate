//! Test-plan rows C4-C7: the combination of Cedar and the approvals gate (section 4).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::{ActionClass, BlockReason, GateDecision};
use entropa_policy::*;

#[test]
fn c4_ai_principals_cannot_do_hard_rule_actions_humans_need_a_non_attested_approval() {
    let e = reference();
    let ai = decide(
        &e,
        &req(class(ActionClass::Delete), RoleName::Ai),
        &allowed(false),
    );
    assert_eq!((ai.outcome, ai.reason), (Outcome::Deny, Reason::CedarDeny));
    assert!(ai
        .determining
        .contains(&"hard-rule-actions-need-a-human".to_string()));
    let human = decide(
        &e,
        &req(class(ActionClass::Delete), RoleName::Human),
        &allowed(false),
    );
    assert_eq!(
        (human.outcome, human.reason, human.cedar),
        (Outcome::Allow, Reason::Allowed, Some(Outcome::Allow))
    );
    let pending = decide(
        &e,
        &req(class(ActionClass::Delete), RoleName::Human),
        &blocked(BlockReason::Pending),
    );
    assert_eq!(
        (pending.outcome, pending.reason),
        (Outcome::Deny, Reason::GateBlocked(BlockReason::Pending))
    );
}

#[test]
fn c5_a_deploy_is_allowed_only_for_a_non_attested_approval() {
    let e = reference();
    for block in BLOCKS {
        let d = decide(
            &e,
            &req(class(ActionClass::Deploy), RoleName::Ai),
            &blocked(block),
        );
        assert_eq!(d.outcome, Outcome::Deny, "{block:?}");
    }
    assert_eq!(
        decide(
            &e,
            &req(class(ActionClass::Deploy), RoleName::Ai),
            &allowed(true)
        )
        .outcome,
        Outcome::Deny
    );
    assert_eq!(
        decide(
            &e,
            &req(class(ActionClass::Deploy), RoleName::Ai),
            &allowed(false)
        )
        .outcome,
        Outcome::Allow
    );
}

#[test]
fn c5_the_approval_state_placed_in_the_cedar_context_follows_the_gate() {
    let e = reference();
    let state =
        |g: &GateDecision| decide(&e, &req(Action::ReadLog, RoleName::Human), g).approval_state;
    assert_eq!(state(&blocked(BlockReason::NoRequest)), "none");
    assert_eq!(state(&blocked(BlockReason::Pending)), "pending");
    assert_eq!(state(&blocked(BlockReason::Denied)), "denied");
    assert_eq!(state(&blocked(BlockReason::Expired)), "expired");
    assert_eq!(state(&blocked(BlockReason::AlreadyUsed)), "used");
    assert_eq!(state(&blocked(BlockReason::SubjectMismatch)), "none");
    assert_eq!(
        state(&blocked(BlockReason::AttestationNotAccepted)),
        "attestation_only"
    );
    assert_eq!(state(&allowed(false)), "approved");
    assert_eq!(state(&allowed(true)), "attestation_only");
}

/// The code guard: whatever the policy text says, a hard-rule class never opens on an attestation
/// or without an approval.
#[test]
fn c6_a_permissive_policy_cannot_open_a_hard_rule_class() {
    let e = permissive();
    for hard in [
        ActionClass::Delete,
        ActionClass::Spend,
        ActionClass::Publish,
        ActionClass::CredentialsChange,
    ] {
        let attested = decide(&e, &req(class(hard), RoleName::Human), &allowed(true));
        assert_eq!(
            (attested.outcome, attested.reason),
            (Outcome::Deny, Reason::AttestationNotAccepted),
            "{hard:?}"
        );
        for block in BLOCKS {
            let d = decide(&e, &req(class(hard), RoleName::Human), &blocked(block));
            assert_eq!(
                (d.outcome, d.reason),
                (Outcome::Deny, Reason::GateBlocked(block)),
                "{hard:?} {block:?}"
            );
        }
        assert_eq!(
            decide(&e, &req(class(hard), RoleName::Human), &allowed(false)).outcome,
            Outcome::Allow,
            "{hard:?}"
        );
    }
}

#[test]
fn c6_attestation_opens_direction_only() {
    let e = permissive();
    assert_eq!(
        decide(
            &e,
            &req(class(ActionClass::Direction), RoleName::Human),
            &allowed(true)
        )
        .outcome,
        Outcome::Allow
    );
    for other in [
        ActionClass::Merge,
        ActionClass::Deploy,
        ActionClass::PolicyChange,
    ] {
        let d = decide(&e, &req(class(other), RoleName::Human), &allowed(true));
        assert_eq!(
            (d.outcome, d.reason),
            (Outcome::Deny, Reason::AttestationNotAccepted),
            "{other:?}"
        );
    }
}

/// Section 4's decision table, row by row.
#[test]
fn c7_the_decision_table() {
    let deny_all = closed();
    let allow_all = permissive();
    // Cedar Deny: always Deny, whatever the evidence
    for g in [allowed(false), allowed(true), blocked(BlockReason::Pending)] {
        let d = decide(&deny_all, &req(Action::ReadLog, RoleName::Human), &g);
        assert_eq!((d.outcome, d.reason), (Outcome::Deny, Reason::CedarDeny));
    }
    // Cedar Allow, not guarded: Allow whatever the gate says
    for a in [Action::ReadLog, Action::AppendRecord, Action::CallTool] {
        for g in [
            allowed(false),
            allowed(true),
            blocked(BlockReason::NoRequest),
            blocked(BlockReason::Denied),
        ] {
            assert_eq!(
                decide(&allow_all, &req(a, RoleName::Human), &g).outcome,
                Outcome::Allow,
                "{a:?} {g:?}"
            );
        }
    }
    // Cedar Allow, guarded: needs the gate; attested counts for direction only
    for c in ActionClass::ALL {
        let ok = decide(&allow_all, &req(class(c), RoleName::Human), &allowed(false));
        assert_eq!(
            (ok.outcome, ok.reason),
            (Outcome::Allow, Reason::Allowed),
            "{c:?}"
        );
        let att = decide(&allow_all, &req(class(c), RoleName::Human), &allowed(true));
        if c == ActionClass::Direction {
            assert_eq!(att.outcome, Outcome::Allow);
            assert!(att.approval_attested);
        } else {
            assert_eq!(
                (att.outcome, att.reason),
                (Outcome::Deny, Reason::AttestationNotAccepted),
                "{c:?}"
            );
        }
        for b in BLOCKS {
            let d = decide(&allow_all, &req(class(c), RoleName::Human), &blocked(b));
            assert_eq!(
                (d.outcome, d.reason),
                (Outcome::Deny, Reason::GateBlocked(b)),
                "{c:?} {b:?}"
            );
        }
    }
}

#[test]
fn production_is_closed_to_attested_approvals_by_the_reference_policy() {
    let e = reference();
    let mut r = req(class(ActionClass::Direction), RoleName::Human);
    r.env = Env::Prod;
    let d = decide(&e, &r, &allowed(true));
    assert_eq!(
        (d.outcome, d.cedar),
        (Outcome::Allow, Some(Outcome::Allow)),
        "direction stays open: the reference forbid exempts it"
    );
    let mut r = req(class(ActionClass::Merge), RoleName::Human);
    r.env = Env::Prod;
    assert_eq!(decide(&e, &r, &allowed(true)).outcome, Outcome::Deny);
}
