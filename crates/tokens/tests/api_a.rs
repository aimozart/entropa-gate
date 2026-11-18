//! AT1 task 2 (red first): the API of design A. These tests are written before the library exists.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tokens::{issue_a, narrow_a, verify_a, Claims, Deny, Policy, Tier, Trust};

const NOW: u64 = 1_800_000_000;
fn claims(id: &str) -> Claims {
    Claims {
        token_id: id.repeat(32)[..32].to_string(),
        subject: "agent-7".into(),
        tier: Tier::T2,
        corpora: vec!["a".repeat(64), "b".repeat(64)],
        actions: vec!["lookup_clause".into(), "search".into()],
        spend_cap: 5_000_000,
        rate_cap: 60,
        not_before: NOW - 10,
        expiry: NOW + 600,
        audience: "node-1".into(),
        parent: None,
    }
}
fn policy() -> Policy {
    Policy {
        audience: "node-1".into(),
        now: NOW,
        ..Policy::default()
    }
}
fn world() -> (Probe, Trust) {
    let p = Probe::spawn();
    let mut t = Trust::default();
    t.add(&p.pubkey_hex());
    (p, t)
}

#[test]
fn a1_an_issued_token_verifies_offline_and_returns_its_claims() {
    let (p, t) = world();
    let tok = issue_a(&p, &claims("1")).unwrap();
    let v = verify_a(
        &tok,
        &t,
        &policy(),
        Some(&entropa_tokens::empty_revocations(&p, NOW)),
        None,
    )
    .unwrap();
    assert_eq!(v.claims, {
        let mut c = claims("1");
        c.parent = None;
        c
    });
}

#[test]
fn a2_a_token_is_refused_by_a_verifier_that_does_not_trust_the_issuer() {
    let (p, _) = world();
    let tok = issue_a(&p, &claims("2")).unwrap();
    let other = Trust::default();
    let r = verify_a(
        &tok,
        &other,
        &policy(),
        Some(&entropa_tokens::empty_revocations(&p, NOW)),
        None,
    );
    assert_eq!(r.unwrap_err(), Deny::UnknownKey);
}

#[test]
fn a3_time_audience_and_ttl_rules() {
    let (p, t) = world();
    let rev = entropa_tokens::empty_revocations(&p, NOW);
    let tok = issue_a(&p, &claims("3")).unwrap();
    let at = |now: u64| verify_a(&tok, &t, &Policy { now, ..policy() }, Some(&rev), None);
    // the empty revocation list was issued at NOW; keep the clock inside its age for the time tests
    assert!(at(NOW).is_ok());
    assert_eq!(
        at(NOW + 600).unwrap_err(),
        Deny::Expired,
        "no grace on expiry"
    );
    let early = Claims {
        not_before: NOW + 100,
        ..claims("3")
    };
    let tok2 = issue_a(&p, &early).unwrap();
    let at2 = |now: u64| {
        verify_a(
            &tok2,
            &t,
            &Policy { now, ..policy() },
            Some(&entropa_tokens::empty_revocations(&p, now)),
            None,
        )
    };
    assert_eq!(at2(NOW + 69).unwrap_err(), Deny::NotYetValid);
    assert!(at2(NOW + 70).is_ok(), "30 seconds early is allowed");
    let wrong = Policy {
        audience: "node-2".into(),
        ..policy()
    };
    assert_eq!(
        verify_a(&tok, &t, &wrong, Some(&rev), None).unwrap_err(),
        Deny::WrongAudience
    );
    let long = Claims {
        expiry: NOW + 4000,
        ..claims("3")
    };
    let tok3 = issue_a(&p, &long).unwrap();
    assert_eq!(
        verify_a(&tok3, &t, &policy(), Some(&rev), None).unwrap_err(),
        Deny::TtlTooLong
    );
}

#[test]
fn a4_revocation_is_checked_and_fails_closed() {
    let (p, t) = world();
    let tok = issue_a(&p, &claims("4")).unwrap();
    assert_eq!(
        verify_a(&tok, &t, &policy(), None, None).unwrap_err(),
        Deny::RevocationMissing
    );
    let revoked = entropa_tokens::issue_revocations(
        &p,
        NOW,
        &[(
            claims("4").token_id,
            NOW - 5,
            entropa_tokens::Reason::Compromise,
        )],
    );
    assert_eq!(
        verify_a(&tok, &t, &policy(), Some(&revoked), None).unwrap_err(),
        Deny::Revoked
    );
    let stale = entropa_tokens::empty_revocations(&p, NOW - 301);
    assert_eq!(
        verify_a(&tok, &t, &policy(), Some(&stale), None).unwrap_err(),
        Deny::RevocationStale
    );
    let edge = entropa_tokens::empty_revocations(&p, NOW - 300);
    assert!(
        verify_a(&tok, &t, &policy(), Some(&edge), None).is_ok(),
        "exactly the maximum age is still fresh"
    );
    let other = Probe::spawn();
    let forged = entropa_tokens::empty_revocations(&other, NOW);
    assert_eq!(
        verify_a(&tok, &t, &policy(), Some(&forged), None).unwrap_err(),
        Deny::RevocationInvalid
    );
}

#[test]
fn a5_narrowing_by_the_issuer_never_widens_and_links_to_the_parent() {
    let (p, t) = world();
    let rev = entropa_tokens::empty_revocations(&p, NOW);
    let parent = issue_a(&p, &claims("5")).unwrap();
    let child_claims = Claims {
        token_id: "c".repeat(32),
        tier: Tier::T1,
        corpora: vec!["a".repeat(64)],
        actions: vec!["search".into()],
        spend_cap: 1_000,
        rate_cap: 10,
        not_before: NOW,
        expiry: NOW + 300,
        ..claims("5")
    };
    let child = narrow_a(&p, &parent, &child_claims).unwrap();
    let v = verify_a(&child, &t, &policy(), Some(&rev), Some(&parent)).unwrap();
    assert_eq!(
        v.claims.parent.as_deref(),
        Some(claims("5").token_id.as_str())
    );
    // every widening is refused when the child is made
    let widen: Vec<Claims> = vec![
        Claims {
            corpora: vec!["a".repeat(64), "c".repeat(64)],
            ..child_claims.clone()
        },
        Claims {
            actions: vec!["delete_everything".into()],
            ..child_claims.clone()
        },
        Claims {
            spend_cap: 5_000_001,
            ..child_claims.clone()
        },
        Claims {
            rate_cap: 61,
            ..child_claims.clone()
        },
        Claims {
            tier: Tier::T3,
            ..child_claims.clone()
        },
        Claims {
            expiry: NOW + 601,
            ..child_claims.clone()
        },
        Claims {
            not_before: NOW - 11,
            ..child_claims.clone()
        },
        Claims {
            audience: "node-2".into(),
            ..child_claims.clone()
        },
    ];
    for w in widen {
        assert!(narrow_a(&p, &parent, &w).is_err(), "{w:?}");
    }
}
