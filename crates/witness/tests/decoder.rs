//! Test-plan row W10: the strict decoders for requests and statements.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_witness::*;
use serde_json::{json, Value};

fn base() -> Value {
    let log = log_with(5);
    request_value(&log.log_id(), &log.checkpoint(5, TS), &log.proof(3, 5))
}

fn dec(v: &Value) -> Result<Request, WitnessError> {
    match decode_request(&v.to_string()) {
        Err(WitnessError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        other => other,
    }
}

fn is_invalid(r: Result<Request, WitnessError>) -> bool {
    matches!(
        r,
        Err(WitnessError::Invalid(_)) | Err(WitnessError::Limit(_))
    )
}

#[test]
fn w10_a_good_request_decodes_and_nothing_is_echoed_in_errors() {
    let r = dec(&base()).unwrap();
    assert_eq!(r.checkpoint.size, 5);
    assert_eq!(r.consistency.len(), 4);
    let mut bad = base();
    bad["log_id"] = json!("SECRET-LOOKING-VALUE");
    match dec(&bad) {
        Err(WitnessError::Invalid(m)) => assert!(
            !m.contains("SECRET-LOOKING-VALUE"),
            "the offending value must not be echoed: {m}"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn w10_unknown_missing_and_mistyped_fields_are_refused() {
    let mut cases: Vec<(&str, Value)> = Vec::new();
    let mut v = base();
    v["extra"] = json!(1);
    cases.push(("unknown top-level field", v));
    let mut v = base();
    v["checkpoint"]["extra"] = json!(1);
    cases.push(("unknown checkpoint field", v));
    for key in ["v", "log_id", "checkpoint", "consistency"] {
        let mut v = base();
        v.as_object_mut().unwrap().remove(key);
        cases.push((key, v));
    }
    for key in ["root", "size", "timestamp", "proposer_pubkey", "signature"] {
        let mut v = base();
        v["checkpoint"].as_object_mut().unwrap().remove(key);
        cases.push((key, v));
    }
    let mut v = base();
    v["v"] = json!(2);
    cases.push(("version 2", v));
    let mut v = base();
    v["v"] = json!("1");
    cases.push(("version as string", v));
    for (name, size) in [
        ("size as string", json!("5")),
        ("size as float", json!(5.0)),
        ("size negative", json!(-1)),
        ("size 2^53", json!(1u64 << 53)),
        ("size 2^64", json!(u64::MAX)),
    ] {
        let mut v = base();
        v["checkpoint"]["size"] = size;
        cases.push((name, v));
    }
    let mut v = base();
    v["checkpoint"]["timestamp"] = json!(u64::MAX);
    cases.push(("timestamp too large", v));
    let mut v = base();
    v["consistency"] = json!("not an array");
    cases.push(("consistency not an array", v));
    let mut v = base();
    v["checkpoint"] = json!([1, 2]);
    cases.push(("checkpoint not an object", v));
    for (name, v) in cases {
        assert!(is_invalid(dec(&v)), "{name} must be refused");
    }
    for raw in ["", "null", "[]", "42", "\"x\"", "{", "{\"v\":1,}", "\u{0}"] {
        match decode_request(raw) {
            Err(WitnessError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
            r => assert!(is_invalid(r), "{raw:?}"),
        }
    }
}

#[test]
fn w10_hex_fields_must_be_exact_lowercase_hex() {
    let log_id = log_with(1).log_id();
    let mut cases: Vec<(&str, Value)> = Vec::new();
    let set = |path: &[&str], val: Value| {
        let mut v = base();
        let mut cur = &mut v;
        for p in &path[..path.len() - 1] {
            cur = &mut cur[*p];
        }
        cur[path[path.len() - 1]] = val;
        v
    };
    cases.push((
        "log_id uppercase",
        set(&["log_id"], json!(log_id.to_uppercase())),
    ));
    cases.push(("log_id 63 chars", set(&["log_id"], json!(&log_id[..63]))));
    cases.push(("log_id not hex", set(&["log_id"], json!("g".repeat(64)))));
    cases.push((
        "root uppercase",
        set(&["checkpoint", "root"], json!("AB".repeat(32))),
    ));
    cases.push((
        "root 62 chars",
        set(&["checkpoint", "root"], json!("ab".repeat(31))),
    ));
    cases.push(("root empty", set(&["checkpoint", "root"], json!(""))));
    cases.push((
        "signature uppercase",
        set(&["checkpoint", "signature"], json!("AB".repeat(100))),
    ));
    cases.push((
        "signature odd length",
        set(&["checkpoint", "signature"], json!("abc")),
    ));
    cases.push((
        "signature empty",
        set(&["checkpoint", "signature"], json!("")),
    ));
    cases.push((
        "pubkey uppercase",
        set(&["checkpoint", "proposer_pubkey"], json!("AB".repeat(100))),
    ));
    cases.push((
        "proof element uppercase",
        set(&["consistency"], json!(["AB".repeat(32)])),
    ));
    cases.push((
        "proof element short",
        set(&["consistency"], json!(["ab".repeat(31)])),
    ));
    cases.push((
        "proof element not a string",
        set(&["consistency"], json!([1])),
    ));
    for (name, v) in cases {
        assert!(is_invalid(dec(&v)), "{name} must be refused");
    }
}

#[test]
fn w10_size_limits_and_deep_nesting_are_refused_without_panicking() {
    let mut v = base();
    v["consistency"] = json!(vec!["ab".repeat(32); MAX_PROOF_LEN]);
    assert!(dec(&v).is_ok(), "exactly MAX_PROOF_LEN hashes is fine");
    v["consistency"] = json!(vec!["ab".repeat(32); MAX_PROOF_LEN + 1]);
    assert!(
        matches!(dec(&v), Err(WitnessError::Limit(_))),
        "one more is a Limit error"
    );
    let mut big = base();
    big["pad"] = json!("x".repeat(MAX_REQUEST_BYTES));
    assert!(
        matches!(dec(&big), Err(WitnessError::Limit(_))),
        "a body over MAX_REQUEST_BYTES is a Limit error"
    );
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    match decode_request(&deep) {
        Err(WitnessError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        r => assert!(is_invalid(r)),
    }
}

fn good_statement() -> (String, String) {
    let log = log_with(4);
    let (w, _) = witness(&log, true);
    let _ = cosign_ok(&w, &body(&log.log_id(), &log.checkpoint(4, TS), &[]), NOW);
    let json = w
        .cosign(&body(&log.log_id(), &log.checkpoint(4, TS), &[]), NOW + 1)
        .unwrap();
    (json, w.pubkey_hex())
}

#[test]
fn w10_the_statement_decoder_is_strict_and_verification_needs_the_right_key() {
    let (json, pk) = good_statement();
    let st = verify_statement(&json, &pk).unwrap();
    assert_eq!(st.fields.size, 4);
    let other = log_with(1).pubkey();
    assert_eq!(
        verify_statement(&json, &other),
        Err(WitnessError::BadSignature)
    );
    let base: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(base.as_object().unwrap().len(), 11, "exact field set: v, type, log_id, size, root, log_timestamp, witness_time, previous_size, previous_root, witness_pubkey, sig");
    assert_eq!(base["type"], STATEMENT_TYPE);
    let mutate = |f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v);
        v.to_string()
    };
    let tampered: Vec<(&str, String)> = vec![
        ("size changed", mutate(&|v| v["size"] = json!(5))),
        (
            "root changed",
            mutate(&|v| v["root"] = json!("ab".repeat(32))),
        ),
        (
            "witness_time changed",
            mutate(&|v| v["witness_time"] = json!(1)),
        ),
        (
            "previous_size changed",
            mutate(&|v| v["previous_size"] = json!(1)),
        ),
    ];
    for (name, s) in tampered {
        assert_eq!(
            verify_statement(&s, &pk),
            Err(WitnessError::BadSignature),
            "{name}"
        );
    }
    let malformed: Vec<(&str, String)> = vec![
        ("unknown field", mutate(&|v| v["extra"] = json!(1))),
        (
            "missing sig",
            mutate(&|v| {
                v.as_object_mut().unwrap().remove("sig");
            }),
        ),
        (
            "wrong type",
            mutate(&|v| v["type"] = json!("witness.other")),
        ),
        ("version 2", mutate(&|v| v["v"] = json!(2))),
        (
            "uppercase root",
            mutate(&|v| v["root"] = json!("AB".repeat(32))),
        ),
        ("size as string", mutate(&|v| v["size"] = json!("4"))),
        ("size 2^53", mutate(&|v| v["size"] = json!(1u64 << 53))),
        ("empty sig", mutate(&|v| v["sig"] = json!(""))),
        ("odd sig", mutate(&|v| v["sig"] = json!("abc"))),
        ("not an object", "[]".to_string()),
    ];
    for (name, s) in malformed {
        match decode_statement(&s) {
            Err(WitnessError::Invalid(_)) | Err(WitnessError::Limit(_)) => {}
            other => panic!("{name}: {other:?}"),
        }
    }
}
