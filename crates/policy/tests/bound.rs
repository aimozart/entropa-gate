//! S4d: the always-available constructor binds the engine to the directory.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::{ActionClass, Actor, Directory, Role};
use entropa_policy::*;

fn dir(role: Role) -> Directory {
    let mut d = Directory::default();
    d.actors.insert(
        PRINCIPAL.to_string(),
        Actor {
            pubkey_hex: "ab".into(),
            role,
            may_approve: vec![],
            may_attest_for: vec![],
            revoked_at: None,
        },
    );
    d
}

fn bound(d: Directory) -> Engine {
    Engine::new_bound(SCHEMA, POLICIES, d).unwrap()
}

#[test]
fn n1_new_bound_takes_the_role_from_the_directory_not_the_request() {
    let ai = bound(dir(Role::Ai));
    let r = req(class(ActionClass::Delete), RoleName::Human);
    assert_eq!(
        ai.decide(&r, &allowed(false), Mode::Enforce).outcome,
        Outcome::Deny
    );
    let human = bound(dir(Role::Human));
    let r = req(class(ActionClass::Delete), RoleName::Ai);
    assert_eq!(
        human.decide(&r, &allowed(false), Mode::Enforce).outcome,
        Outcome::Allow
    );
}

#[test]
fn n2_an_unknown_principal_is_denied() {
    let e = bound(Directory::default());
    let d = e.decide(
        &req(Action::ReadLog, RoleName::Human),
        &allowed(false),
        Mode::Enforce,
    );
    assert_eq!(
        (d.outcome, d.reason),
        (Outcome::Deny, Reason::InvalidRequest)
    );
}
