//! EG1f red tests, part 2: the containment layer (a stage record (not published)). Expected results come from the plan's rules, not from the code. Red against the stub (`check` refuses everything,
//! `decide_contained` refuses everything).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common_f;
use common_f::*;
use entropa_egress::contain::{check, Contained, Kind, Refusal, Schema};
use entropa_egress::decide::Action;
use entropa_egress::v2::decide_contained;
use serde_json::{json, Value};

fn schema() -> Schema {
    Schema {
        fields: vec![
            (
                "status".into(),
                Kind::Code(vec!["open".into(), "closed".into(), "hold".into()]),
            ),
            ("digest".into(), Kind::Hash),
            ("ref".into(), Kind::Id { max: 32 }),
            ("count".into(), Kind::Int { min: 0, max: 1000 }),
            ("urgent".into(), Kind::Bool),
            ("note".into(), Kind::FreeText { max: 2000 }),
        ],
    }
}
fn ok_payload() -> Value {
    json!({"status": "open", "digest": "ab".repeat(32), "ref": "claim-0042", "count": 7, "urgent": true})
}
fn chk(v: &Value) -> Result<Contained, Refusal> {
    check(&schema(), v.to_string().as_bytes())
}

#[test]
fn y1_a_payload_of_typed_fields_passes_and_carries_no_free_text() {
    let c = chk(&ok_payload()).expect("typed fields must pass");
    assert!(c.free_text.is_empty());
    let mut with_note = ok_payload();
    with_note["note"] = json!("the claim was reviewed on Monday");
    let c = chk(&with_note).unwrap();
    assert_eq!(
        c.free_text,
        vec![(
            "note".to_string(),
            "the claim was reviewed on Monday".to_string()
        )]
    );
    assert!(
        check(&schema(), b"{}").is_ok(),
        "an empty object is fine: every declared field is optional"
    );
}

#[test]
fn y2_every_kind_of_violation_is_refused_with_its_own_code() {
    let mut cases: Vec<(Value, Refusal)> = vec![];
    let with = |k: &str, v: Value| {
        let mut p = ok_payload();
        p[k] = v;
        p
    };
    cases.push((with("status", json!("deleted")), Refusal::OutOfRange));
    cases.push((with("status", json!(5)), Refusal::WrongType));
    cases.push((with("digest", json!("ab".repeat(31))), Refusal::OutOfRange));
    cases.push((with("digest", json!("AB".repeat(32))), Refusal::OutOfRange));
    cases.push((with("digest", json!(5)), Refusal::WrongType));
    cases.push((with("ref", json!("has space")), Refusal::OutOfRange));
    cases.push((with("ref", json!("a".repeat(33))), Refusal::TooLong));
    cases.push((with("ref", json!("")), Refusal::OutOfRange));
    cases.push((with("count", json!(1001)), Refusal::OutOfRange));
    cases.push((with("count", json!(-1)), Refusal::OutOfRange));
    cases.push((with("count", json!(1.5)), Refusal::WrongType));
    cases.push((with("count", json!("7")), Refusal::WrongType));
    cases.push((with("urgent", json!("yes")), Refusal::WrongType));
    cases.push((with("note", json!("x".repeat(2001))), Refusal::TooLong));
    cases.push((with("note", json!(5)), Refusal::WrongType));
    cases.push((with("extra", json!("anything")), Refusal::UnknownField));
    cases.push((with("status", json!({"a": 1})), Refusal::Nested));
    cases.push((with("status", json!(["open"])), Refusal::Nested));
    cases.push((json!(["open"]), Refusal::NotObject));
    cases.push((json!("open"), Refusal::NotObject));
    for (p, want) in cases {
        assert_eq!(chk(&p).unwrap_err(), want, "{p}");
    }
    assert_eq!(check(&schema(), b"not json").unwrap_err(), Refusal::NotJson);
    assert_eq!(
        check(&schema(), &[0xff, 0xfe]).unwrap_err(),
        Refusal::NotJson
    );
    assert_eq!(check(&schema(), b"").unwrap_err(), Refusal::NotJson);
    assert_eq!(
        check(&schema(), br#"{"status":"open","status":"closed"}"#).unwrap_err(),
        Refusal::DuplicateKey
    );
    let big = format!("{{\"note\":\"{}\"}}", "a".repeat(70_000));
    assert_eq!(
        check(&schema(), big.as_bytes()).unwrap_err(),
        Refusal::TooLarge
    );
}

#[test]
fn y3_no_dev_secret_family_can_leave_through_a_typed_field() {
    // every one of the 1,080 DEV secret bodies, placed in each typed kind and in an undeclared field, is refused; placed in the free-text field it passes the schema (the guard then decides)
    let secrets = cases("eval_dev_f", "eg_secrets.jsonl");
    assert_eq!(secrets.len(), 1080);
    for c in &secrets {
        let body = c["body"].as_str().unwrap();
        for field in ["status", "digest", "ref", "count", "urgent"] {
            let mut p = ok_payload();
            p[field] = json!(body);
            assert!(
                chk(&p).is_err(),
                "{}: the body passed through the typed field {field}",
                c["id"]
            );
        }
        let mut p = ok_payload();
        p["sidecar"] = json!(body);
        assert_eq!(chk(&p).unwrap_err(), Refusal::UnknownField, "{}", c["id"]);
        let mut p = ok_payload();
        p["note"] = json!(body);
        if body.len() <= 2000 {
            assert_eq!(
                chk(&p).unwrap().free_text.len(),
                1,
                "{}: the declared free-text field must pass the schema",
                c["id"]
            );
        }
    }
}

#[test]
fn y4_a_refusal_never_contains_the_payload_a_field_name_or_a_value() {
    let canary = format!("{}{}", "ENTROPA-CANARY-", "0011223344556677");
    let p = json!({format!("{canary}-field"): canary.clone(), "status": canary.clone()});
    let e = chk(&p).unwrap_err();
    assert_eq!(
        e,
        Refusal::UnknownField,
        "an undeclared field is the first thing refused"
    );
    assert!(
        !format!("{e:?}").contains(&canary) && !format!("{e}").contains("CANARY"),
        "the refusal echoes the payload"
    );
}

#[test]
fn y5_the_contained_decision_runs_free_text_through_the_guard_and_the_worst_action_wins() {
    let pol = policy_of("eval_dev_f");
    let run = |payload: &Value| {
        decide_contained(
            &schema(),
            payload.to_string().as_bytes(),
            &pol,
            entropa_egress::policy::Tier::T1,
            &conv(),
            &Null,
        )
    };
    // typed only: allowed without any free text
    assert_eq!(run(&ok_payload()).unwrap().action, Action::Allow);
    // harmless free text: allowed
    let mut p = ok_payload();
    p["note"] = json!("The claim was reviewed on Monday.");
    assert_eq!(run(&p).unwrap().action, Action::Allow);
    // a secret in the declared free-text field: blocked by the guard
    p["note"] = json!(format!("{} = \"{}\"", "password", "Xk39fQ2zLpA9"));
    assert_eq!(run(&p).unwrap().action, Action::Block);
    // a secret in an undeclared field: refused before the guard
    let mut q = ok_payload();
    q["comment"] = json!("password = \"Xk39fQ2zLpA9\"");
    assert_eq!(run(&q).unwrap_err(), Refusal::UnknownField);
    // an unparsable payload: refused
    assert_eq!(
        decide_contained(
            &schema(),
            b"password=abc",
            &pol,
            entropa_egress::policy::Tier::T1,
            &conv(),
            &Null
        )
        .unwrap_err(),
        Refusal::NotJson
    );
}

#[test]
fn y6_hostile_payloads_never_panic_and_always_end_in_a_refusal_or_a_decision() {
    let pol = policy_of("eval_dev_f");
    let frags = [
        "{",
        "}",
        "\"note\"",
        "\"status\"",
        ":",
        ",",
        "\"open\"",
        "\"",
        "\\u0000",
        "\\",
        "é",
        "日本",
        "[",
        "]",
        "null",
        "1e999",
        "-0",
        "\"count\"",
        "99999999999999999999",
        "\"digest\"",
        "\u{1F600}",
    ];
    let mut x: u64 = 0xDEAD_BEEF_0BAD_F00D;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..30_000 {
        let n = 1 + (next() % 12) as usize;
        let mut s = String::new();
        for _ in 0..n {
            s.push_str(frags[(next() % frags.len() as u64) as usize]);
        }
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = check(&schema(), s.as_bytes());
            let _ = decide_contained(
                &schema(),
                s.as_bytes(),
                &pol,
                entropa_egress::policy::Tier::T1,
                &conv(),
                &Null,
            );
        }));
        assert!(r.is_ok(), "panic on {s:?}");
    }
}
