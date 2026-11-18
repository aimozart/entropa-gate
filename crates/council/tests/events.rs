//! Closed-code events: golden vectors from an independent generator, strict decoder, signatures, role table.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("vectors/council_v1.json");

#[test]
fn e1_golden_canonical_bytes_and_digests_match_an_independent_implementation() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 3);
    for c in cases {
        let e = must(decode_event(&payload_of(&c["event"])));
        let cb = canonical_bytes(&e);
        assert_eq!(
            String::from_utf8(cb.clone()).unwrap(),
            c["canonical"].as_str().unwrap(),
            "{}",
            c["name"]
        );
        assert_eq!(
            hex::encode(event_digest(&cb)),
            c["digest"].as_str().unwrap(),
            "{}",
            c["name"]
        );
        assert_eq!(e.canonical_json(), c["canonical"].as_str().unwrap());
    }
}

#[test]
fn e2_every_event_type_decodes_and_reports_its_type_and_session() {
    for kind in ALL_KINDS {
        let e = ev(kind, json!({}));
        assert_eq!(e.event_type(), kind);
        let bound = !matches!(
            kind,
            "outcome.recorded" | "precedent.referenced" | "evaluation.recorded"
        );
        assert_eq!(
            e.session_id(),
            if bound { Some(SID) } else { None },
            "{kind}"
        );
        let c = e.canonical_json();
        assert!(
            !c.contains("\"sig\""),
            "{kind}: the canonical form never holds the signature"
        );
        assert!(!c.contains(' ') && !c.contains('\n'), "{kind}: compact");
        let parsed: Value = serde_json::from_str(&c).unwrap();
        let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        // serde_json may preserve insertion order, so the canonical TEXT must already be sorted: compare positions
        let mut last = 0usize;
        for k in sorted {
            let pos = c.find(&format!("\"{k}\":")).unwrap();
            assert!(pos >= last, "{kind}: key {k} out of order");
            last = pos;
        }
    }
}

#[test]
fn e3_sign_and_verify_every_event_type_and_refuse_tampering_and_other_keys() {
    let p = Probe::spawn();
    let other = Probe::spawn();
    for kind in ALL_KINDS {
        let signed = must(sign_event(&p, &unsigned(kind, json!({})).to_string()));
        must(verify_event(&signed, &p.pubkey_hex()));
        assert!(
            matches!(
                verify_event(&signed, &other.pubkey_hex()),
                Err(CouncilError::Verify(_))
            ),
            "{kind}: wrong key"
        );
        let mut t: Value = serde_json::from_str(&signed).unwrap();
        t["ts"] = json!(NOW + 101);
        assert!(
            matches!(
                verify_event(&t.to_string(), &p.pubkey_hex()),
                Err(CouncilError::Verify(_))
            ),
            "{kind}: tampered ts"
        );
    }
}

#[test]
fn e4_the_signed_digest_is_domain_separated() {
    let c = canonical_bytes(&ev("session.closed", json!({})));
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-approval-v1\0");
    h.update(&(c.len() as u32).to_be_bytes());
    h.update(&c);
    assert_ne!(
        event_digest(&c),
        *h.finalize().as_bytes(),
        "a council signature must not verify as an approvals signature"
    );
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-council-v1\0");
    h.update(&(c.len() as u32).to_be_bytes());
    h.update(&c);
    assert_eq!(event_digest(&c), *h.finalize().as_bytes());
}

#[test]
fn e5_the_decoder_refuses_every_bad_finding() {
    let base = unsigned("finding.submitted", json!({}));
    let with = |k: &str, x: Value| {
        let mut v = base.clone();
        v[k] = x;
        // payload_of() would overwrite a bad `sig` with a valid one; the sig rows must reach the decoder as written
        if k == "sig" {
            v.to_string()
        } else {
            payload_of(&v)
        }
    };
    let without = |k: &str| {
        let mut v = base.clone();
        v.as_object_mut().unwrap().remove(k);
        payload_of(&v)
    };
    let nine: Vec<Value> = (0..9)
        .map(|i| json!({"kind":"ledger_index","ref":format!("idx:{i}")}))
        .collect();
    let bad: Vec<(&str, String)> = vec![
        ("unknown field text", with("text", json!("free text"))),
        ("unknown field comment", with("comment", json!("x"))),
        ("unknown field note", with("note", json!("x"))),
        ("version 2", with("v", json!(2))),
        ("version string", with("v", json!("1"))),
        ("missing class", without("class")),
        ("missing evidence", without("evidence")),
        ("missing actor", without("actor")),
        ("missing alg", without("alg")),
        ("empty alg", with("alg", json!(""))),
        ("alg with a space", with("alg", json!("ML DSA"))),
        ("alg of 33 characters", with("alg", json!("A".repeat(33)))),
        ("alg not a string", with("alg", json!(65))),
        ("missing sig", {
            let mut v = base.clone();
            v.as_object_mut().unwrap().remove("sig");
            v.to_string()
        }),
        (
            "upper-case session id",
            with("session_id", json!("A".repeat(64))),
        ),
        (
            "short session id",
            with("session_id", json!("a".repeat(63))),
        ),
        (
            "non-hex session id",
            with("session_id", json!("g".repeat(64))),
        ),
        ("actor not 16 hex", with("actor", json!("0123"))),
        ("token with a space", with("finding_id", json!("f 1"))),
        ("token with a newline", with("finding_id", json!("f\n1"))),
        (
            "token of 65 characters",
            with("finding_id", json!("f".repeat(65))),
        ),
        ("empty token", with("finding_id", json!(""))),
        ("unicode token", with("finding_id", json!("f-\u{00e9}"))),
        ("unknown class", with("class", json!("cosmic_ray"))),
        ("unknown severity", with("severity", json!("critical"))),
        ("unknown confidence", with("confidence", json!("certain"))),
        (
            "unknown proposed change",
            with("proposed_change", json!("rewrite_everything")),
        ),
        ("unknown provider", with("provider", json!("openai"))),
        ("nine evidence items", with("evidence", json!(nine))),
        (
            "evidence kind unknown",
            with("evidence", json!([{"kind":"hearsay","ref":"x"}])),
        ),
        (
            "evidence item with an extra field",
            with(
                "evidence",
                json!([{"kind":"ledger_index","ref":"idx:1","why":"x"}]),
            ),
        ),
        ("evidence not an array", with("evidence", json!("idx:1"))),
        ("text_hash not hex", with("text_hash", json!("hello"))),
        ("ts as string", with("ts", json!("1800000000"))),
        ("ts negative", with("ts", json!(-1))),
        ("ts float", with("ts", json!(1.5))),
        ("sig upper-case", with("sig", json!("ABCD"))),
        ("sig empty", with("sig", json!(""))),
        ("sig odd length", with("sig", json!("abc"))),
        ("unknown type", with("type", json!("finding.invented"))),
        ("not JSON", "{".to_string()),
        ("a JSON array", "[]".to_string()),
        ("null", "null".to_string()),
    ];
    for (name, p) in bad {
        assert!(
            matches!(decode_event(&p), Err(CouncilError::Invalid(_))),
            "{name} was accepted"
        );
    }
}

#[test]
fn e6_the_decoder_refuses_bad_values_in_every_other_type() {
    let cases: Vec<(&str, Value)> = vec![
        ("session.opened", json!({"cadence":"daily"})),
        ("session.opened", json!({"trigger":"whim"})),
        (
            "session.opened",
            json!({"period_start": NOW, "period_end": NOW - 1}),
        ),
        ("session.opened", json!({"expires": NOW})),
        ("session.opened", json!({"window_hash":"xyz"})),
        ("report.submitted", json!({"findings_hash":"abc"})),
        ("rebuttal.submitted", json!({"stance":"maybe"})),
        ("rebuttal.submitted", json!({"counter":"because"})),
        (
            "packet.compiled",
            json!({"items":[{"finding_id":"f-1","check":"trust_me","recommendation":"accept"}]}),
        ),
        (
            "packet.compiled",
            json!({"items":[{"finding_id":"f-1","check":"verified","recommendation":"maybe"}]}),
        ),
        (
            "packet.compiled",
            json!({"items":[{"finding_id":"f-1","check":"verified","recommendation":"accept","extra":1}]}),
        ),
        ("packet.compiled", json!({"item_count": 2})),
        ("decision.recorded", json!({"decision":"approve"})),
        ("decision.recorded", json!({"reason":"felt_right"})),
        ("decision.recorded", json!({"change_kind":"rewrite"})),
        ("decision.recorded", json!({"attested":"no"})),
        ("decision.recorded", json!({"auth_ref":"not hex"})),
        ("change.linked", json!({"change_kind":"none"})),
        ("proof.recorded", json!({"n_changed": 51})),
        (
            "proof.recorded",
            json!({"newly_denied": 4, "newly_allowed": 1}),
        ),
        ("session.closed", json!({"closing":"gave_up"})),
        ("outcome.recorded", json!({"outcome":"great"})),
        ("outcome.recorded", json!({"source":"vibes"})),
        (
            "precedent.referenced",
            json!({"precedent_ids":["a","b","c","d","e","f"]}),
        ),
        ("precedent.referenced", json!({"k": 0})),
        ("precedent.referenced", json!({"k": 6})),
        ("precedent.referenced", json!({"followed":"sort_of"})),
        ("evaluation.recorded", json!({"detection_permille": 1001})),
        ("evaluation.recorded", json!({"reviewer_provider":"openai"})),
    ];
    for (kind, over) in cases {
        assert!(
            matches!(
                decode_event(&payload(kind, over.clone())),
                Err(CouncilError::Invalid(_))
            ),
            "{kind} {over}"
        );
    }
}

#[test]
fn e7_no_free_text_field_exists_in_any_event_type() {
    // Every string value of every valid event is a closed code, a hex hash, an id token or a reference: never free text.
    for kind in ALL_KINDS {
        let v = unsigned(kind, json!({}));
        for (k, x) in v.as_object().unwrap() {
            for forbidden in [
                "text",
                "comment",
                "note",
                "message",
                "body",
                "description",
                "summary",
                "prompt",
                "answer",
                "name",
            ] {
                assert_ne!(k, forbidden, "{kind} has a free-text-looking field {k}");
            }
            if let Some(s) = x.as_str() {
                assert!(s.len() <= 64, "{kind}.{k}");
            }
        }
        // And the decoder refuses every one of those names if a client adds it.
        for forbidden in [
            "text",
            "comment",
            "note",
            "message",
            "body",
            "description",
            "summary",
            "prompt",
            "answer",
        ] {
            let p = payload(kind, json!({ forbidden: "anything" }));
            assert!(
                matches!(decode_event(&p), Err(CouncilError::Invalid(_))),
                "{kind} accepted field {forbidden}"
            );
        }
    }
}

#[test]
fn e8_a_canary_token_can_never_enter_an_event() {
    // P0: a canary-shaped token is charset-valid for an id, a model id or a reference; the decoder must still refuse it.
    let canary = entropa_synthetic::canary(7);
    assert!(canary.starts_with("ENTROPA-CANARY-"));
    let places: Vec<(&str, Value)> = vec![
        ("finding.submitted", json!({"finding_id": canary})),
        ("finding.submitted", json!({"model_id": canary})),
        ("finding.submitted", json!({"subject_ref": canary})),
        (
            "finding.submitted",
            json!({"evidence": [{"kind":"ledger_index","ref": canary}]}),
        ),
        ("decision.recorded", json!({"approval_ref": canary})),
        ("change.linked", json!({"ref": canary})),
        ("rebuttal.submitted", json!({"model_id": canary})),
        ("outcome.recorded", json!({"decision_ref": canary})),
        ("precedent.referenced", json!({"precedent_ids": [canary]})),
        ("evaluation.recorded", json!({"reviewer_model_id": canary})),
    ];
    for (kind, over) in places {
        assert!(
            matches!(
                decode_event(&payload(kind, over.clone())),
                Err(CouncilError::Invalid(_))
            ),
            "{kind} {over}"
        );
        let p = Probe::spawn();
        assert!(
            sign_event(&p, &unsigned(kind, over.clone()).to_string()).is_err(),
            "{kind} signed a canary"
        );
    }
}

#[test]
fn e9_the_role_that_may_write_each_event_type() {
    let table = [
        ("session.opened", Role::Scheduler),
        ("session.closed", Role::Scheduler),
        ("session.expired", Role::Scheduler),
        ("proof.recorded", Role::Scheduler),
        ("evaluation.recorded", Role::Scheduler),
        ("finding.submitted", Role::Critic),
        ("report.submitted", Role::Critic),
        ("rebuttal.submitted", Role::Contestor),
        ("packet.compiled", Role::Orchestrator),
        ("decision.recorded", Role::Human),
        ("change.linked", Role::Builder),
        ("outcome.recorded", Role::Generator),
        ("precedent.referenced", Role::Agent),
        ("carryover.recorded", Role::Orchestrator),
    ];
    for (kind, role) in table {
        assert_eq!(required_role(kind), Some(role), "{kind}");
    }
    assert_eq!(required_role("finding.invented"), None);
    assert_eq!(ALL_KINDS.len(), table.len());
}

#[test]
fn e10_providers_families_and_the_independence_rule() {
    assert_eq!(Provider::parse("bedrock"), Some(Provider::Bedrock));
    assert_eq!(Provider::parse("vertex"), Some(Provider::Vertex));
    assert_eq!(Provider::parse("fake"), Some(Provider::Fake));
    assert_eq!(Provider::parse("openai"), None);
    assert_eq!(Provider::Bedrock.family(), Family::Nova);
    assert_eq!(Provider::Vertex.family(), Family::Gemini);
    assert!(independent(Family::Gemini, Family::Nova));
    assert!(independent(Family::Nova, Family::Gemini));
    assert!(!independent(Family::Nova, Family::Nova));
    assert!(!independent(Family::Gemini, Family::Gemini));
    assert!(
        independent(Family::Fake, Family::Nova)
            && independent(Family::Nova, Family::Fake)
            && independent(Family::Fake, Family::Fake),
        "the fake backend is exempt"
    );
}
