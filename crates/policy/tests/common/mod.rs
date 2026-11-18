//! Shared helpers. All data is synthetic.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_approvals::{ActionClass, BlockReason, GateDecision};
use entropa_policy::*;

pub const SCHEMA: &str = include_str!("../../../../policies/entropa.cedarschema");
pub const POLICIES: &str = include_str!("../../../../policies/entropa.cedar");
pub const NOW: u64 = 1_700_000_000;
pub const PRINCIPAL: &str = "fedcba9876543210";
pub const ACTOR: &str = "0123456789abcdef";

pub fn load(schema: &str, policies: &str) -> Engine {
    match Engine::new(schema, policies) {
        Ok(e) => e,
        Err(PolicyError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => panic!("engine did not load: {e:?}"),
    }
}

pub fn reference() -> Engine {
    load(SCHEMA, POLICIES)
}

/// An engine whose Cedar side allows everything.
pub fn permissive() -> Engine {
    load(
        SCHEMA,
        r#"@id("allow-all") permit(principal, action, resource);"#,
    )
}

/// An engine whose Cedar side denies everything (no permit at all).
pub fn closed() -> Engine {
    load(SCHEMA, "")
}

pub fn subject(word: &str) -> String {
    hex::encode(blake3::hash(word.as_bytes()).as_bytes())
}

pub fn req(action: Action, role: RoleName) -> Request {
    Request {
        principal: PRINCIPAL.into(),
        role,
        has_key: true,
        action,
        subject_hash: subject("subject-1"),
        subject_kind: "command".into(),
        now: NOW,
        env: Env::Dev,
    }
}

pub fn class(c: ActionClass) -> Action {
    Action::Class(c)
}

pub fn allowed(attested: bool) -> GateDecision {
    GateDecision::Allowed {
        request_id: subject("rid"),
        approver: ACTOR.into(),
        attested,
    }
}

pub fn blocked(r: BlockReason) -> GateDecision {
    GateDecision::Blocked(r)
}

pub const BLOCKS: [BlockReason; 7] = [
    BlockReason::NoRequest,
    BlockReason::Pending,
    BlockReason::Denied,
    BlockReason::Expired,
    BlockReason::AlreadyUsed,
    BlockReason::SubjectMismatch,
    BlockReason::AttestationNotAccepted,
];

/// Decide, failing with the explicit red reason while the stub answers.
pub fn decide(e: &Engine, r: &Request, g: &GateDecision) -> Decision {
    let d = e.decide(r, g, Mode::Enforce);
    assert!(
        d.reason != Reason::NotImplemented,
        "decide: {NOT_IMPLEMENTED}"
    );
    d
}
