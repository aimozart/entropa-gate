//! The sealed set schema `entropa-sealed-v1`: what is accepted and every refusal. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_check::set::parse;

fn one(extra: &str) -> String {
    format!(
        r#"{{"schema":"entropa-sealed-v1","cases":[{{"id":"c-1","class":"k","input":{{"text":"hello"}},"expect":"block"{extra}}}]}}"#
    )
}

#[test]
fn s1_a_minimal_set_parses_with_defaults() {
    let s = parse(one("").as_bytes()).unwrap();
    assert_eq!(s.cases.len(), 1);
    let c = &s.cases[0];
    assert_eq!(
        (c.id.as_str(), c.class.as_str(), c.expect.as_str()),
        ("c-1", "k", "block")
    );
    assert_eq!(c.input, b"hello");
    assert!(!c.attack && c.secrets.is_empty());
    assert_eq!(c.timeout_ms, 5000);
}

#[test]
fn s2_hex_input_attack_secrets_and_timeout() {
    let s = parse(
        one(r#","attack":true,"secrets":["abc"],"timeout_ms":250"#)
            .replace(r#"{"text":"hello"}"#, r#"{"hex":"00ff41"}"#)
            .as_bytes(),
    )
    .unwrap();
    let c = &s.cases[0];
    assert_eq!(c.input, vec![0x00, 0xff, 0x41]);
    assert!(c.attack);
    assert_eq!(c.secrets, vec!["abc".to_string()]);
    assert_eq!(c.timeout_ms, 250);
}

fn refused(doc: &str, why: &str) {
    let e = parse(doc.as_bytes()).unwrap_err();
    assert!(
        !e.0.contains("hello"),
        "the refusal must not echo input: {e}"
    );
    assert!(
        !e.0.contains("not yet implemented"),
        "{why}: still the red-phase stub"
    );
}

#[test]
fn s3_every_refusal() {
    refused("not json", "not json");
    refused(
        r#"{"schema":"entropa-sealed-v2","cases":[]}"#,
        "unknown schema",
    );
    refused(
        r#"{"schema":"entropa-sealed-v1","cases":[],"extra":1}"#,
        "unknown top-level field",
    );
    refused(&one(r#","surprise":1"#), "unknown case field");
    refused(
        &one("").replace(r#""id":"c-1""#, r#""id":"c 1""#),
        "id outside the pattern",
    );
    refused(
        &one("").replace(r#""class":"k""#, r#""class":"k/k""#),
        "class outside the pattern",
    );
    refused(
        &one("").replace(r#""expect":"block""#, r#""expect":"maybe""#),
        "expect outside the closed words",
    );
    refused(
        &one("").replace(r#"{"text":"hello"}"#, r#"{"text":"a","hex":"00"}"#),
        "both text and hex",
    );
    refused(
        &one("").replace(r#"{"text":"hello"}"#, r#"{"hex":"0g"}"#),
        "bad hex",
    );
    refused(&one(r#","timeout_ms":60001"#), "timeout over the limit");
    refused(&one(r#","timeout_ms":0"#), "timeout zero");
    refused(
        r#"{"schema":"entropa-sealed-v1","cases":[{"id":"a","id":"b","class":"k","input":{"text":"x"},"expect":"block"}]}"#,
        "duplicate key",
    );
    let dup = r#"{"id":"c-1","class":"k","input":{"text":"x"},"expect":"block"}"#;
    refused(
        &format!(r#"{{"schema":"entropa-sealed-v1","cases":[{dup},{dup}]}}"#),
        "duplicate ids",
    );
}

#[test]
fn s4_size_limits() {
    let big = "a".repeat(1024 * 1024 + 1);
    refused(&one("").replace("hello", &big), "input over 1 MiB");
    let ok = "a".repeat(1024 * 1024);
    assert!(
        parse(one("").replace("hello", &ok).as_bytes()).is_ok(),
        "exactly 1 MiB is accepted"
    );
    let many: Vec<String> = (0..5001)
        .map(|i| format!(r#"{{"id":"c{i}","class":"k","input":{{"text":"x"}},"expect":"allow"}}"#))
        .collect();
    refused(
        &format!(
            r#"{{"schema":"entropa-sealed-v1","cases":[{}]}}"#,
            many.join(",")
        ),
        "more than 5,000 cases",
    );
    let many: Vec<String> = (0..5000)
        .map(|i| format!(r#"{{"id":"c{i}","class":"k","input":{{"text":"x"}},"expect":"allow"}}"#))
        .collect();
    assert_eq!(
        parse(
            format!(
                r#"{{"schema":"entropa-sealed-v1","cases":[{}]}}"#,
                many.join(",")
            )
            .as_bytes()
        )
        .unwrap()
        .cases
        .len(),
        5000
    );
}
