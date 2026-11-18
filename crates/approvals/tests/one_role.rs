//! P3.3 (docs/CONTROLS-MAP.md, gap T-C): a key never holds two roles; the directory refuses a second identity for a key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_approvals::{ActionClass, Actor, ApprovalError, Directory, Role};

fn actor(key: &str, role: Role) -> Actor {
    Actor {
        pubkey_hex: key.to_string(),
        role,
        may_approve: vec![ActionClass::ALL[0]],
        may_attest_for: vec![],
        revoked_at: None,
    }
}

#[test]
fn c1_a_new_key_is_registered_and_an_identical_re_registration_is_idempotent() {
    let mut d = Directory::new();
    let id = d.try_add(actor("aa", Role::Human)).unwrap();
    assert_eq!(d.try_add(actor("aa", Role::Human)).unwrap(), id);
    assert_eq!(d.actors.len(), 1);
}

#[test]
fn c2_the_same_key_with_another_role_is_refused_for_every_pair_and_changes_nothing() {
    let roles = [Role::Human, Role::Ai, Role::Service];
    for first in roles {
        for second in roles.into_iter().filter(|r| *r != first) {
            let mut d = Directory::new();
            let id = d.try_add(actor("bb", first)).unwrap();
            let before = d.actors.clone();
            assert!(
                matches!(
                    d.try_add(actor("bb", second)),
                    Err(ApprovalError::Invalid(_))
                ),
                "{first:?} then {second:?}"
            );
            assert_eq!(d.actors, before, "the directory is unchanged");
            assert_eq!(d.actors[&id].role, first);
        }
    }
}

#[test]
fn c3_a_changed_scope_or_a_revocation_is_not_a_silent_re_registration() {
    let mut d = Directory::new();
    d.try_add(actor("cc", Role::Ai)).unwrap();
    let mut wider = actor("cc", Role::Ai);
    wider.may_approve = ActionClass::ALL.to_vec();
    assert!(
        matches!(d.try_add(wider), Err(ApprovalError::Invalid(_))),
        "wider approval scope"
    );
    let mut attest = actor("cc", Role::Ai);
    attest.may_attest_for = vec!["dd".into()];
    assert!(
        matches!(d.try_add(attest), Err(ApprovalError::Invalid(_))),
        "attestation scope"
    );
    let mut revoked = actor("cc", Role::Ai);
    revoked.revoked_at = Some(3);
    assert!(
        matches!(d.try_add(revoked), Err(ApprovalError::Invalid(_))),
        "revocation state"
    );
    assert_eq!(d.actors.values().next().unwrap().may_approve.len(), 1);
}

#[test]
fn c4_two_different_keys_are_two_actors() {
    let mut d = Directory::new();
    let a = d.try_add(actor("ee", Role::Human)).unwrap();
    let b = d.try_add(actor("ff", Role::Ai)).unwrap();
    assert_ne!(a, b);
    assert_eq!(d.actors.len(), 2);
}
