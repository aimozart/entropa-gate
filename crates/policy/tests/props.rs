//! Test-plan row P1: the invariant of the combination over random requests and gate results.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::{ActionClass, GateDecision};
use entropa_policy::*;
use proptest::prelude::*;

fn actions() -> Vec<Action> {
    let mut v = vec![Action::ReadLog, Action::AppendRecord, Action::CallTool];
    v.extend(ActionClass::ALL.into_iter().map(Action::Class));
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    /// P1: a final Allow needs a Cedar Allow; a guarded action needs an Allowed gate; a hard-rule
    /// action additionally needs that approval to be non-attested; an attested approval only ever
    /// opens `direction`; unguarded actions never depend on the gate.
    #[test]
    fn p1_the_final_allow_always_has_its_evidence(
        a in 0usize..11, role in 0usize..3, prod in any::<bool>(), g in 0usize..9, which_engine in 0usize..3,
    ) {
        let engines = [reference(), permissive(), closed()];
        let engine = &engines[which_engine];
        let action = actions()[a];
        let role = [RoleName::Human, RoleName::Ai, RoleName::Service][role];
        let gate = match g {
            0..=6 => blocked(BLOCKS[g]),
            7 => allowed(false),
            _ => allowed(true),
        };
        let mut r = req(action, role);
        r.env = if prod { Env::Prod } else { Env::Dev };
        let d = decide(engine, &r, &gate);
        if d.outcome == Outcome::Allow {
            prop_assert_eq!(d.cedar, Some(Outcome::Allow));
            if let Action::Class(c) = action {
                let gate_allowed = matches!(gate, GateDecision::Allowed { .. });
                prop_assert!(gate_allowed);
                if let GateDecision::Allowed { attested, .. } = gate {
                    if attested { prop_assert_eq!(c, ActionClass::Direction); }
                    if matches!(c, ActionClass::Delete | ActionClass::Spend | ActionClass::Publish | ActionClass::CredentialsChange) {
                        prop_assert!(!attested);
                    }
                }
            }
        }
        if which_engine == 2 { prop_assert_eq!(d.outcome, Outcome::Deny); }
    }
}
