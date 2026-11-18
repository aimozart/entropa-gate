//! AT1 task 2 (red first): the API of design C (append-only chain of signed blocks).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tokens::{append_c, issue_c, verify_c, Claims, Deny, Narrowing, Policy, Tier, Trust};

const NOW: u64 = 1_800_000_000;
fn claims() -> Claims {
    Claims {
        token_id: "d".repeat(32),
        subject: "agent-9".into(),
        tier: Tier::T2,
        corpora: vec!["a".repeat(64), "b".repeat(64), "c".repeat(64)],
        actions: vec!["cite_check".into(), "lookup_clause".into(), "search".into()],
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
fn world() -> (Probe, Trust, Vec<u8>) {
    let p = Probe::spawn();
    let mut t = Trust::default();
    t.add(&p.pubkey_hex());
    let rev = entropa_tokens::empty_revocations(&p, NOW);
    (p, t, rev)
}

#[test]
fn c1_a_root_and_three_appended_blocks_verify_and_the_effective_claims_only_narrow() {
    let (p, t, rev) = world();
    let w0 = issue_c(&p, &claims()).unwrap();
    assert_eq!(
        verify_c(&w0.token, &t, &policy(), Some(&rev))
            .unwrap()
            .claims,
        claims()
    );
    let w1 = append_c(
        &w0,
        &Narrowing {
            corpora: Some(vec!["a".repeat(64), "b".repeat(64)]),
            ..Narrowing::default()
        },
    )
    .unwrap();
    let w2 = append_c(
        &w1,
        &Narrowing {
            actions: Some(vec!["search".into()]),
            spend_cap: Some(100),
            ..Narrowing::default()
        },
    )
    .unwrap();
    let w3 = append_c(
        &w2,
        &Narrowing {
            tier: Some(Tier::T0),
            expiry: Some(NOW + 60),
            rate_cap: Some(5),
            ..Narrowing::default()
        },
    )
    .unwrap();
    let v = verify_c(&w3.token, &t, &policy(), Some(&rev)).unwrap();
    assert_eq!(v.chain_len, 4);
    assert_eq!(v.claims.tier, Tier::T0);
    assert_eq!(v.claims.corpora, vec!["a".repeat(64), "b".repeat(64)]);
    assert_eq!(v.claims.actions, vec!["search".to_string()]);
    assert_eq!(
        (v.claims.spend_cap, v.claims.rate_cap, v.claims.expiry),
        (100, 5, NOW + 60)
    );
    // each hop is a longer token (a 3.3 KB signature and a next key per block)
    assert!(
        w1.token.len() > w0.token.len()
            && w2.token.len() > w1.token.len()
            && w3.token.len() > w2.token.len()
    );
}

#[test]
fn c2_the_library_refuses_to_append_a_widening_block() {
    let (p, _, _) = world();
    let w = issue_c(&p, &claims()).unwrap();
    for n in [
        Narrowing {
            corpora: Some(vec!["a".repeat(64), "e".repeat(64)]),
            ..Narrowing::default()
        },
        Narrowing {
            actions: Some(vec!["admin".into()]),
            ..Narrowing::default()
        },
        Narrowing {
            spend_cap: Some(5_000_001),
            ..Narrowing::default()
        },
        Narrowing {
            rate_cap: Some(61),
            ..Narrowing::default()
        },
        Narrowing {
            tier: Some(Tier::T3),
            ..Narrowing::default()
        },
        Narrowing {
            expiry: Some(NOW + 601),
            ..Narrowing::default()
        },
        Narrowing {
            not_before: Some(NOW - 11),
            ..Narrowing::default()
        },
    ] {
        assert!(append_c(&w, &n).is_err(), "{n:?}");
    }
}

#[test]
fn c3_a_block_that_widens_is_refused_by_the_verifier_even_when_correctly_signed() {
    let (p, t, rev) = world();
    let w = issue_c(&p, &claims()).unwrap();
    // a holder with the real key signs a block that adds a corpus: the signature is valid, the content is not allowed
    let bad = entropa_tokens::testing::append_c_unchecked(
        &w,
        &Narrowing {
            corpora: Some(vec!["a".repeat(64), "e".repeat(64)]),
            ..Narrowing::default()
        },
    );
    assert_eq!(
        verify_c(&bad.token, &t, &policy(), Some(&rev)).unwrap_err(),
        Deny::Widened
    );
}

#[test]
fn c4_the_root_signature_must_come_from_a_trusted_key_and_blocks_from_the_committed_keys() {
    let (p, t, rev) = world();
    let w = issue_c(&p, &claims()).unwrap();
    let w1 = append_c(
        &w,
        &Narrowing {
            tier: Some(Tier::T1),
            ..Narrowing::default()
        },
    )
    .unwrap();
    assert!(verify_c(&w1.token, &t, &policy(), Some(&rev)).is_ok());
    assert_eq!(
        verify_c(&w1.token, &Trust::default(), &policy(), Some(&rev)).unwrap_err(),
        Deny::UnknownKey
    );
    // a block signed by a key that the previous block did not commit to
    let evil = Probe::spawn();
    let forged = entropa_tokens::testing::append_c_with_key(
        &w,
        &Narrowing {
            tier: Some(Tier::T1),
            ..Narrowing::default()
        },
        &evil,
    );
    assert_eq!(
        verify_c(&forged.token, &t, &policy(), Some(&rev)).unwrap_err(),
        Deny::BadSignature
    );
}

#[test]
fn c5_revoking_the_root_revokes_every_descendant() {
    let (p, t, _) = world();
    let w = issue_c(&p, &claims()).unwrap();
    let w1 = append_c(
        &w,
        &Narrowing {
            tier: Some(Tier::T1),
            ..Narrowing::default()
        },
    )
    .unwrap();
    let rev = entropa_tokens::issue_revocations(
        &p,
        NOW,
        &[(
            claims().token_id,
            NOW - 1,
            entropa_tokens::Reason::Requested,
        )],
    );
    assert_eq!(
        verify_c(&w1.token, &t, &policy(), Some(&rev)).unwrap_err(),
        Deny::Revoked
    );
}

#[test]
fn c6_at_most_eight_blocks() {
    let (p, _, _) = world();
    let mut w = issue_c(&p, &claims()).unwrap();
    let mut n = 0;
    while let Ok(next) = append_c(
        &w,
        &Narrowing {
            spend_cap: Some(5_000_000 - n),
            ..Narrowing::default()
        },
    ) {
        w = next;
        n += 1;
        if n > 20 {
            break;
        }
    }
    assert_eq!(n, 7, "the root plus seven appended blocks");
}

#[test]
fn c7_the_verifier_refuses_a_token_with_more_than_seven_appended_blocks() {
    let (p, t, rev) = world();
    let mut w = issue_c(&p, &claims()).unwrap();
    for i in 0..8 {
        w = entropa_tokens::testing::append_c_unlimited(
            &w,
            &Narrowing {
                spend_cap: Some(5_000_000 - 1 - i),
                ..Narrowing::default()
            },
        );
    }
    assert_eq!(
        verify_c(&w.token, &t, &policy(), Some(&rev)).unwrap_err(),
        Deny::TooManyBlocks
    );
}
