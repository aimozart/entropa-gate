//! LS3a red tests (a stage record (not published)): the CONTRACT of the "Try the gate" handler, with no network and no deployment. Expected statuses and codes come from the plan's table; the signed record is
//! checked with the ledger's own verifier (independent of this crate); the closed reason list comes from the egress crate. Synthetic data only; secret-shaped values are built from parts at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_egress::decide::Reason;
use entropa_ledger::{decode_event, verify_event, Decision, Kind, LabelCode};
use entropa_try::{Config, HttpRequest, Response, Service, ERROR_CODES, LABEL};
use serde_json::Value;

const NOW: u64 = 1_800_000_000;
fn probe() -> Probe {
    Probe::from_signing_key_hex(&format!("{:02x}", 11u8).repeat(32)).unwrap()
}
fn svc() -> Service {
    Service::new(probe(), Config::default())
}
fn call(s: &Service, client: &str, ct: &str, body: &[u8], now: u64) -> Response {
    s.handle(
        &HttpRequest {
            content_type: ct,
            client,
            body,
        },
        now,
    )
}
fn json(s: &Service, text: &str, tier: &str) -> Response {
    let body = serde_json::json!({"text": text, "tier": tier}).to_string();
    call(s, "client-a", "application/json", body.as_bytes(), NOW)
}
fn v(r: &Response) -> Value {
    serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", r.body))
}
fn err_code(r: &Response) -> String {
    v(r)["error"].as_str().unwrap_or("").to_string()
}
fn keys(x: &Value) -> Vec<String> {
    let mut k: Vec<String> = x.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

#[test]
fn k1_an_ordinary_text_is_allowed_with_a_signed_record_and_exactly_the_documented_fields() {
    let r = json(&svc(), "How many claims were denied last month?", "T1");
    assert_eq!(r.status, 200, "{}", r.body);
    let b = v(&r);
    assert_eq!(keys(&b), ["decision", "label", "reasons", "record", "tier"]);
    assert_eq!(b["label"], LABEL);
    assert_eq!(b["tier"], "T1");
    assert_eq!(b["decision"], "allow");
    assert_eq!(keys(&b["record"]), ["event", "key_id", "pubkey"]);
    let pk = probe().pubkey_hex();
    assert_eq!(b["record"]["pubkey"], pk);
    // the record verifies with the ledger's own verifier and says what the contract says
    let ev =
        verify_event(b["record"]["event"].as_str().unwrap(), &pk).expect("the record must verify");
    assert_eq!(ev.fields.kind, Kind::parse("evidence.policy").unwrap());
    assert_eq!(ev.fields.label, LabelCode::parse("policy_verdict").unwrap());
    assert_eq!(ev.fields.decision, Decision::Allow);
    assert_eq!(ev.fields.ts, NOW);
    assert_eq!(b["record"]["key_id"], ev.fields.key_id);
}

#[test]
fn k2_a_secret_shaped_text_is_blocked_with_closed_reason_codes_and_a_deny_record() {
    let aws = format!("my key is AKIA{}", "IOSFODNN7EXAMPLE");
    let r = json(&svc(), &aws, "T1");
    assert_eq!(r.status, 200, "{}", r.body);
    let b = v(&r);
    assert_eq!(b["decision"], "block");
    let closed: Vec<&str> = Reason::ALL.iter().map(|x| x.as_str()).collect();
    let reasons = b["reasons"].as_array().unwrap();
    assert!(!reasons.is_empty());
    for x in reasons {
        assert!(
            closed.contains(&x.as_str().unwrap()),
            "reason outside the closed list: {x}"
        );
    }
    let ev = verify_event(
        b["record"]["event"].as_str().unwrap(),
        &probe().pubkey_hex(),
    )
    .unwrap();
    assert_eq!(ev.fields.decision, Decision::Deny);
}

#[test]
fn k3_every_tier_answers_with_the_same_shape_and_an_unknown_tier_is_refused() {
    let s = svc();
    for t in ["T0", "T1", "T2", "T3"] {
        let r = json(&s, "hello there", t);
        assert_eq!(r.status, 200, "{t}: {}", r.body);
        assert_eq!(v(&r)["tier"], t);
    }
    for bad in ["T4", "t1", "", "T1 ", "ALL"] {
        let r = json(&s, "hello", bad);
        assert_eq!(
            (r.status, err_code(&r).as_str()),
            (400, "bad_tier"),
            "{bad:?}"
        );
    }
}

#[test]
fn k4_the_size_limit_is_exact_and_the_content_type_must_be_json() {
    let s = svc();
    let pad = |n: usize| {
        let mut b = String::from("{\"text\":\"");
        let tail = "\",\"tier\":\"T1\"}";
        b.push_str(&"a".repeat(n - b.len() - tail.len()));
        b.push_str(tail);
        assert_eq!(b.len(), n);
        b
    };
    assert_eq!(
        call(&s, "c", "application/json", pad(4096).as_bytes(), NOW).status,
        200,
        "exactly the limit is accepted"
    );
    let big = call(&s, "c", "application/json", pad(4097).as_bytes(), NOW);
    assert_eq!((big.status, err_code(&big).as_str()), (413, "too_large"));
    for ct in [
        "application/json",
        "application/json; charset=utf-8",
        "Application/JSON",
    ] {
        assert_eq!(
            call(&s, "c", ct, pad(100).as_bytes(), NOW).status,
            200,
            "{ct}"
        );
    }
    for ct in [
        "text/plain",
        "application/jsonp",
        "application/x-www-form-urlencoded",
        "",
        "application/json2",
    ] {
        let r = call(&s, "c", ct, pad(100).as_bytes(), NOW);
        assert_eq!(
            (r.status, err_code(&r).as_str()),
            (415, "bad_content_type"),
            "{ct:?}"
        );
    }
}

#[test]
fn k5_malformed_bodies_are_refused_with_their_own_code_and_never_echoed() {
    let s = svc();
    let canary = &format!("{}{}", "ENTROPA-CANARY-", "0123456789abcdef");
    let cases: Vec<(&str, Vec<u8>, u16, &str)> = vec![
        (
            "invalid utf-8",
            vec![b'{', 0xff, 0xfe, b'}'],
            400,
            "not_utf8",
        ),
        ("not json", b"hello".to_vec(), 400, "not_json"),
        ("an array", b"[1,2]".to_vec(), 400, "not_json"),
        ("empty body", vec![], 400, "not_json"),
        (
            "nesting",
            format!("{}{}", "[".repeat(300), "]".repeat(300)).into_bytes(),
            400,
            "not_json",
        ),
        (
            "duplicate key",
            format!("{{\"text\":\"{canary}\",\"text\":\"b\",\"tier\":\"T1\"}}").into_bytes(),
            400,
            "duplicate_key",
        ),
        (
            "unknown field",
            format!("{{\"text\":\"{canary}\",\"tier\":\"T1\",\"extra\":1}}").into_bytes(),
            400,
            "unknown_field",
        ),
        (
            "missing tier",
            format!("{{\"text\":\"{canary}\"}}").into_bytes(),
            400,
            "missing_field",
        ),
        (
            "missing text",
            b"{\"tier\":\"T1\"}".to_vec(),
            400,
            "missing_field",
        ),
        (
            "text is a number",
            b"{\"text\":5,\"tier\":\"T1\"}".to_vec(),
            400,
            "bad_type",
        ),
        (
            "tier is a number",
            b"{\"text\":\"a\",\"tier\":1}".to_vec(),
            400,
            "bad_type",
        ),
        (
            "NUL in the text",
            b"{\"text\":\"a\\u0000b\",\"tier\":\"T1\"}".to_vec(),
            400,
            "invalid_text",
        ),
        (
            "empty text",
            b"{\"text\":\"\",\"tier\":\"T1\"}".to_vec(),
            400,
            "invalid_text",
        ),
    ];
    for (name, body, status, code) in cases {
        let r = call(
            &s,
            &format!("client-{name}"),
            "application/json",
            &body,
            NOW,
        );
        assert_eq!(
            (r.status, err_code(&r).as_str()),
            (status, code),
            "{name}: {}",
            r.body
        );
        assert_eq!(
            keys(&v(&r)),
            ["error"],
            "{name}: an error answer carries only the code"
        );
        assert!(
            !r.body.contains(canary),
            "{name}: the submitted text was echoed"
        );
    }
}

#[test]
fn k6_the_rate_limit_counts_per_client_resets_with_the_window_and_tells_when_to_retry() {
    let s = svc();
    for i in 0..10 {
        assert_eq!(
            call(
                &s,
                "A",
                "application/json",
                br#"{"text":"hi","tier":"T1"}"#,
                NOW + i / 5
            )
            .status,
            200,
            "request {i}"
        );
    }
    let r = call(
        &s,
        "A",
        "application/json",
        br#"{"text":"hi","tier":"T1"}"#,
        NOW + 2,
    );
    assert_eq!((r.status, err_code(&r).as_str()), (429, "rate_limited"));
    let wait = r.retry_after_secs.expect("a 429 must say when to retry");
    assert!((1..=60).contains(&wait), "retry after {wait}");
    // another client is unaffected; the same client is fine again after the window
    assert_eq!(
        call(
            &s,
            "B",
            "application/json",
            br#"{"text":"hi","tier":"T1"}"#,
            NOW + 2
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &s,
            "A",
            "application/json",
            br#"{"text":"hi","tier":"T1"}"#,
            NOW + 2 + wait
        )
        .status,
        200
    );
    // refused requests still count: a client hammering with bad bodies is limited too
    let s2 = svc();
    for _ in 0..10 {
        assert_eq!(call(&s2, "C", "application/json", b"nope", NOW).status, 400);
    }
    assert_eq!(call(&s2, "C", "application/json", b"nope", NOW).status, 429);
}

#[test]
fn k7_the_limiter_remembers_a_bounded_number_of_clients() {
    let s = Service::new(
        probe(),
        Config {
            max_clients: 1000,
            ..Config::default()
        },
    );
    for i in 0..20_000u32 {
        let c = format!("client-{i}");
        call(
            &s,
            &c,
            "application/json",
            br#"{"text":"hi","tier":"T1"}"#,
            NOW,
        );
    }
    assert!(
        s.tracked_clients() <= 1000,
        "{} clients tracked",
        s.tracked_clients()
    );
    assert!(
        s.tracked_clients() >= 900,
        "the limiter forgot far more than it had to: {}",
        s.tracked_clients()
    );
}

#[test]
fn k8_nothing_the_visitor_sent_is_echoed_or_stored_in_the_answer_or_the_record() {
    let s = svc();
    let canary = &format!("{}{}", "ENTROPA-CANARY-", "fedcba9876543210");
    let r = call(
        &s,
        "10.1.2.3",
        "application/json",
        serde_json::json!({"text": format!("note {canary} end"), "tier": "T1"})
            .to_string()
            .as_bytes(),
        NOW,
    );
    assert_eq!(r.status, 200);
    assert!(!r.body.contains(canary), "the text is echoed");
    assert!(!r.body.contains("10.1.2.3"), "the client key is echoed");
    let b = v(&r);
    let ev = decode_event(b["record"]["event"].as_str().unwrap()).unwrap();
    assert!(
        !format!("{ev:?}").contains(canary),
        "the record holds the text"
    );
    assert!(!b["record"]["event"].as_str().unwrap().contains(canary));
    // the same text twice gives the same subject hash (it is a hash, not a random id) and different texts differ
    let again = v(&call(
        &s,
        "other",
        "application/json",
        serde_json::json!({"text": format!("note {canary} end"), "tier": "T1"})
            .to_string()
            .as_bytes(),
        NOW,
    ));
    let other = v(&call(
        &s,
        "other",
        "application/json",
        serde_json::json!({"text": "something else", "tier": "T1"})
            .to_string()
            .as_bytes(),
        NOW,
    ));
    let h = |x: &Value| {
        decode_event(x["record"]["event"].as_str().unwrap())
            .unwrap()
            .fields
            .subject_hash
    };
    assert_eq!(h(&b), h(&again));
    assert_ne!(h(&b), h(&other));
}

#[test]
fn k9_every_answer_has_a_status_from_the_table_and_an_error_code_from_the_closed_list() {
    // 20,000 hostile bodies built from fragments; none may panic and every answer must be one of the contract's
    let frags = [
        "{",
        "}",
        "\"text\"",
        "\"tier\"",
        ":",
        ",",
        "\"T1\"",
        "\"",
        "\\u0000",
        "\\",
        "é",
        "日本",
        "\u{1F600}",
        "[",
        "]",
        "null",
        "true",
        "1e999",
        "%",
        "AKIA",
        "Bearer ",
        "password=",
        " ",
        "\n",
    ];
    let s = svc();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for i in 0..20_000u32 {
        let n = 1 + (next() % 14) as usize;
        let mut body = String::new();
        for _ in 0..n {
            body.push_str(frags[(next() % frags.len() as u64) as usize]);
        }
        let client = format!("c{}", i % 5000);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            call(
                &s,
                &client,
                "application/json",
                body.as_bytes(),
                NOW + u64::from(i) / 10,
            )
        }));
        let r = r.unwrap_or_else(|_| panic!("panic on {body:?}"));
        assert!(
            [200, 400, 413, 415, 429].contains(&r.status),
            "status {} on {body:?}",
            r.status
        );
        if r.status != 200 {
            assert!(
                ERROR_CODES.contains(&err_code(&r).as_str()) && err_code(&r) != "not_implemented",
                "{}: {body:?}",
                r.body
            );
        }
    }
}

#[test]
fn k10_the_handler_takes_the_time_from_the_caller_and_the_dependency_tree_has_no_network_crate() {
    // the same request at two different caller times gives two different record timestamps: no hidden clock
    let s = svc();
    let ts = |now| {
        decode_event(
            v(&call(
                &s,
                &format!("t{now}"),
                "application/json",
                br#"{"text":"hi","tier":"T1"}"#,
                now,
            ))["record"]["event"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .fields
        .ts
    };
    assert_eq!((ts(NOW), ts(NOW + 12345)), (NOW, NOW + 12345));
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "tree",
            "--offline",
            "-p",
            "entropa-try",
            "-e",
            "normal",
            "--prefix",
            "none",
        ])
        .output()
        .unwrap();
    let t = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(t.contains("entropa-egress"), "an empty tree proves nothing");
    for bad in [
        "reqwest",
        "hyper",
        "axum",
        "tokio",
        "entropa-kms",
        "rustls",
        "openssl",
    ] {
        assert!(
            !t.lines().any(|l| l.starts_with(bad)),
            "{bad} is in the tree"
        );
    }
}
