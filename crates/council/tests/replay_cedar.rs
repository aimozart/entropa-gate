//! The "prove" step against the REAL Cedar engine: current policy set vs a candidate (S12c decision 4). The council
//! source stays free of Cedar; the engine is reached only through a test-side Decider (entropa-policy and
//! entropa-approvals are dev-dependencies of this crate).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::{Actor, BlockReason, Directory, GateDecision, Role as ApRole};
use entropa_policy::{Action, Engine, Env, Mode, Outcome, Request, RoleName};

const SCHEMA: &str = include_str!("../../../policies/entropa.cedarschema");
const CURRENT: &str = include_str!("../../../policies/entropa.cedar");
const PRINCIPAL: &str = "0123456789abcdef";

struct CedarDecider(Engine);

impl CedarDecider {
    fn new(policies: &str) -> CedarDecider {
        let mut d = Directory::default();
        d.actors.insert(
            PRINCIPAL.to_string(),
            Actor {
                pubkey_hex: "ab".into(),
                role: ApRole::Ai,
                may_approve: vec![],
                may_attest_for: vec![],
                revoked_at: None,
            },
        );
        CedarDecider(Engine::new_bound(SCHEMA, policies, d).unwrap())
    }
}

impl Decider for CedarDecider {
    fn decide(&self, input: &str) -> ReplayVerdict {
        let wire = input.strip_prefix("action=").unwrap();
        let req = Request {
            principal: PRINCIPAL.to_string(),
            role: RoleName::Ai,
            has_key: true,
            action: Action::parse(wire).unwrap(),
            subject_hash: "a".repeat(64),
            subject_kind: "synthetic".into(),
            now: NOW,
            env: Env::Dev,
        };
        match self
            .0
            .decide(
                &req,
                &GateDecision::Blocked(BlockReason::NoRequest),
                Mode::Enforce,
            )
            .outcome
        {
            Outcome::Allow => ReplayVerdict::Allow,
            Outcome::Deny => ReplayVerdict::Deny,
        }
    }
}

fn item(id: &str, action: &str, bad: bool) -> ReplayItem {
    let input = format!("action={action}");
    ReplayItem {
        id: id.into(),
        input_hash: input_hash(&input),
        input,
        bad_outcome: bad,
    }
}

fn recorded() -> Vec<ReplayItem> {
    vec![
        item("d-1", "read_log", false),
        item("d-2", "call_tool", true),
        item("d-3", "append_record", false),
        item("d-4", "call_tool", false),
        item("d-5", "deploy", false),
    ]
}

#[test]
fn y1_a_stricter_candidate_policy_denies_what_it_should_and_nothing_else() {
    let current = CedarDecider::new(CURRENT);
    let strict = format!("{CURRENT}\n@id(\"no-tool-calls-for-ai\")\nforbid(principal, action == Action::\"call_tool\", resource) when {{ principal.role == \"ai\" }};\n");
    let r = must(replay(&recorded(), &current, &CedarDecider::new(&strict)));
    assert_eq!(
        (r.replayed, r.changed, r.newly_denied, r.newly_allowed),
        (5, 2, 2, 0)
    );
    assert_eq!(r.changed_ids, vec!["d-2", "d-4"]);
    assert_eq!(
        (r.bad_denied, r.bad_allowed),
        (1, 0),
        "the one bad-outcome decision would have been denied"
    );
}

#[test]
fn y2_loosening_a_policy_shows_up_as_newly_allowed() {
    // current = the strict set, candidate = the base set: the two tool calls become allowed
    let strict = format!("{CURRENT}\n@id(\"no-tool-calls-for-ai\")\nforbid(principal, action == Action::\"call_tool\", resource) when {{ principal.role == \"ai\" }};\n");
    let r = must(replay(
        &recorded(),
        &CedarDecider::new(&strict),
        &CedarDecider::new(CURRENT),
    ));
    assert_eq!((r.changed, r.newly_denied, r.newly_allowed), (2, 0, 2));
    assert_eq!(r.changed_ids, vec!["d-2", "d-4"]);
    assert_eq!(
        (r.bad_denied, r.bad_allowed),
        (0, 1),
        "the bad-outcome decision would be allowed again"
    );
}

#[test]
fn y2b_a_cedar_permit_alone_does_not_allow_a_guarded_action_the_approvals_gate_must_agree() {
    // a candidate that permits deploy for AI agents changes nothing: with no approval on record the gate blocks it
    let current = CedarDecider::new(CURRENT);
    let loose = format!("{CURRENT}\n@id(\"deploy-for-ai\")\npermit(principal, action == Action::\"deploy\", resource) when {{ principal.role == \"ai\" }};\n");
    let r = must(replay(&recorded(), &current, &CedarDecider::new(&loose)));
    assert_eq!(r.changed, 0);
}

#[test]
fn y3_the_unchanged_policy_set_changes_nothing_and_the_baseline_is_what_the_policies_say() {
    let current = CedarDecider::new(CURRENT);
    assert_eq!(current.decide("action=read_log"), ReplayVerdict::Allow);
    assert_eq!(current.decide("action=call_tool"), ReplayVerdict::Allow);
    assert_eq!(
        current.decide("action=deploy"),
        ReplayVerdict::Deny,
        "default deny without an approval"
    );
    let r = must(replay(&recorded(), &current, &CedarDecider::new(CURRENT)));
    assert_eq!((r.changed, r.newly_denied, r.newly_allowed), (0, 0, 0));
}
