//! S4c: with a signed actor directory bound, the principal's role comes only from the directory.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::{ActionClass, Actor, Directory, Role};
use entropa_policy::*;

fn dir(role: Role, key: &str) -> Directory {
    let mut d = Directory::default();
    d.actors.insert(
        PRINCIPAL.to_string(),
        Actor {
            pubkey_hex: key.to_string(),
            role,
            may_approve: vec![],
            may_attest_for: vec![],
            revoked_at: None,
        },
    );
    d
}

#[test]
fn d1_a_request_that_claims_human_is_an_ai_when_the_directory_says_ai() {
    let e = reference().with_directory(dir(Role::Ai, "ab"));
    let d = decide(
        &e,
        &req(class(ActionClass::Delete), RoleName::Human),
        &allowed(false),
    );
    assert_eq!((d.outcome, d.reason), (Outcome::Deny, Reason::CedarDeny));
}

#[test]
fn d2_a_request_that_claims_ai_is_a_human_when_the_directory_says_human() {
    let e = reference().with_directory(dir(Role::Human, "ab"));
    let d = decide(
        &e,
        &req(class(ActionClass::Delete), RoleName::Ai),
        &allowed(false),
    );
    assert_eq!((d.outcome, d.reason), (Outcome::Allow, Reason::Allowed));
}

#[test]
fn d3_key_status_comes_from_the_directory_and_unknown_principals_are_denied() {
    let keyless = reference().with_directory(dir(Role::Ai, ""));
    let mut r = req(Action::AppendRecord, RoleName::Ai);
    r.has_key = true;
    let d = decide(&keyless, &r, &allowed(false));
    assert_eq!(
        d.outcome,
        Outcome::Deny,
        "a keyless directory entry must not append"
    );
    let keyed = reference().with_directory(dir(Role::Ai, "ab"));
    r.has_key = false;
    assert_eq!(decide(&keyed, &r, &allowed(false)).outcome, Outcome::Allow);
    let other = reference().with_directory(Directory::default());
    let d = decide(&other, &r, &allowed(false));
    assert_eq!(
        (d.outcome, d.reason),
        (Outcome::Deny, Reason::InvalidRequest)
    );
}
