//! The two events of the decision-memory design (docs/ARCHITECTURE-MEMORY.md sections 2 and 4): `index.built` (the scheduler
//! signs every index version) and `precedent.revoked` (the human principal withdraws a precedent). Closed codes only,
//! not session-bound. Built with a local helper so the shared kind lists of the accepted tests stay untouched.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use serde_json::{json, Value};

fn base(ty: &str, specific: Value) -> Value {
    let mut v = specific;
    let m = v.as_object_mut().unwrap();
    m.insert("v".into(), json!(1));
    m.insert("type".into(), json!(ty));
    m.insert("alg".into(), json!("ML-DSA-65"));
    m.insert("actor".into(), json!("0123456789abcdef"));
    m.insert("ts".into(), json!(NOW + 100));
    v
}

fn with(mut v: Value, over: Value) -> Value {
    for (k, x) in over.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

fn built(over: Value) -> Value {
    with(
        base(
            "index.built",
            json!({"kind": "lexical", "index_hash": hex64('1'), "n_entries": 5000, "previous_index_hash": hex64('2'), "manifest_hash": hex64('3')}),
        ),
        over,
    )
}

fn revoked(over: Value) -> Value {
    with(
        base(
            "precedent.revoked",
            json!({"precedent_id": "p9", "reason": "wrong_outcome"}),
        ),
        over,
    )
}

#[test]
fn y1_both_events_decode_and_are_not_session_bound() {
    for (v, ty) in [
        (built(json!({})), "index.built"),
        (revoked(json!({})), "precedent.revoked"),
    ] {
        let e = must(decode_event(&payload_of(&v)));
        assert_eq!(e.event_type(), ty);
        assert_eq!(e.session_id(), None);
        assert!(!e.canonical_json().contains("\"sig\""));
    }
    // the first index of all has no previous one
    must(decode_event(&payload_of(&built(
        json!({"previous_index_hash": null}),
    ))));
    must(decode_event(&payload_of(&built(
        json!({"kind": "dense", "n_entries": 0}),
    ))));
}

#[test]
fn y2_the_decoder_refuses_every_bad_field() {
    // positive controls first: the valid events must decode, otherwise every refusal below would be vacuous
    must(decode_event(&payload_of(&built(json!({})))));
    must(decode_event(&payload_of(&revoked(json!({})))));
    let bad: Vec<(&str, Value)> = vec![
        ("unknown kind", built(json!({"kind": "graph"}))),
        ("index_hash not hex", built(json!({"index_hash": "xyz"}))),
        (
            "index_hash upper case",
            built(json!({"index_hash": "A".repeat(64)})),
        ),
        ("manifest_hash short", built(json!({"manifest_hash": "ab"}))),
        (
            "previous 'genesis' text",
            built(json!({"previous_index_hash": "genesis"})),
        ),
        ("n_entries negative", built(json!({"n_entries": -1}))),
        ("n_entries a string", built(json!({"n_entries": "5000"}))),
        (
            "a session id on a session-less event",
            built(json!({"session_id": SID})),
        ),
        (
            "a free-text field",
            built(json!({"note": "rebuilt after the weekly session"})),
        ),
        ("unknown reason", revoked(json!({"reason": "felt_like_it"}))),
        (
            "precedent id with a space",
            revoked(json!({"precedent_id": "p 9"})),
        ),
        ("empty precedent id", revoked(json!({"precedent_id": ""}))),
        ("a session id", revoked(json!({"session_id": SID}))),
        (
            "a free-text field on the revocation",
            revoked(json!({"comment": "looked wrong"})),
        ),
        (
            "a canary as precedent id",
            revoked(json!({"precedent_id": entropa_synthetic::canary(8)})),
        ),
    ];
    for (name, v) in bad {
        assert!(
            matches!(decode_event(&payload_of(&v)), Err(CouncilError::Invalid(_))),
            "{name}"
        );
    }
    for key in [
        "kind",
        "index_hash",
        "n_entries",
        "previous_index_hash",
        "manifest_hash",
        "alg",
        "actor",
    ] {
        let mut v = built(json!({}));
        v.as_object_mut().unwrap().remove(key);
        assert!(
            matches!(decode_event(&payload_of(&v)), Err(CouncilError::Invalid(_))),
            "missing {key}"
        );
    }
    for key in ["precedent_id", "reason"] {
        let mut v = revoked(json!({}));
        v.as_object_mut().unwrap().remove(key);
        assert!(
            matches!(decode_event(&payload_of(&v)), Err(CouncilError::Invalid(_))),
            "missing {key}"
        );
    }
}

#[test]
fn y3_every_revocation_reason_is_a_closed_code() {
    for reason in [
        "wrong_outcome",
        "superseded",
        "policy_changed",
        "poisoned",
        "other",
    ] {
        must(decode_event(&payload_of(&revoked(
            json!({"reason": reason}),
        ))));
    }
}

#[test]
fn y4_the_scheduler_signs_index_versions_and_the_human_principal_signs_revocations() {
    assert_eq!(required_role("index.built"), Some(Role::Scheduler));
    assert_eq!(required_role("precedent.revoked"), Some(Role::Human));
}

#[test]
fn y5_both_events_sign_and_verify_and_tampering_or_another_key_fails() {
    let p = Probe::spawn();
    let other = Probe::spawn();
    for v in [built(json!({})), revoked(json!({}))] {
        let signed = must(sign_event(&p, &v.to_string()));
        must(verify_event(&signed, &p.pubkey_hex()));
        assert!(matches!(
            verify_event(&signed, &other.pubkey_hex()),
            Err(CouncilError::Verify(_))
        ));
        let mut t: Value = serde_json::from_str(&signed).unwrap();
        t["ts"] = json!(NOW + 101);
        assert!(matches!(
            verify_event(&t.to_string(), &p.pubkey_hex()),
            Err(CouncilError::Verify(_))
        ));
    }
    assert!(sign_event(&p, &built(json!({"index_hash": "bad"})).to_string()).is_err());
}

#[test]
fn y6_a_session_does_not_take_them() {
    let mut s = open_session();
    let e = must(decode_event(&payload_of(&built(json!({})))));
    assert!(
        matches!(
            expect_err(s.apply(&e, Role::Scheduler, NOW + 1)),
            CouncilError::Invalid(_)
        ),
        "not a session event"
    );
    let r = must(decode_event(&payload_of(&revoked(json!({})))));
    assert!(matches!(
        expect_err(s.apply(&r, Role::Human, NOW + 1)),
        CouncilError::Invalid(_)
    ));
    assert_eq!(
        expect_err(s.apply(&e, Role::Critic, NOW + 1)),
        CouncilError::WrongRole,
        "wrong role is refused first"
    );
}
