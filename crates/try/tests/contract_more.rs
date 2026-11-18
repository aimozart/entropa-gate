//! LS3a tests written AFTER the green code (so they are not red-first), for what the hostile and mutation runs showed: the redaction wording, the exact edges of the limiter, the order in which it forgets clients,
//! the salt, the configured limits and the mapping from the guard's word to the ledger's. Each is bite-checked by hand mutation (docs/evidence/ls3a/bite.txt).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_ledger::{decode_event, Decision};
use entropa_try::{Config, HttpRequest, Response, Service};
use serde_json::Value;

const NOW: u64 = 1_800_000_000;
fn probe() -> Probe {
    Probe::from_signing_key_hex(&format!("{:02x}", 12u8).repeat(32)).unwrap()
}
fn post(s: &Service, client: &str, text: &str, tier: &str, now: u64) -> Response {
    let body = serde_json::json!({"text": text, "tier": tier}).to_string();
    s.handle(
        &HttpRequest {
            content_type: "application/json",
            client,
            body: body.as_bytes(),
        },
        now,
    )
}
fn v(r: &Response) -> Value {
    serde_json::from_str(&r.body).unwrap()
}
fn ledger_decision(r: &Response) -> (Decision, String) {
    let f = decode_event(v(r)["record"]["event"].as_str().unwrap())
        .unwrap()
        .fields;
    (f.decision, f.reason.as_str().to_string())
}

#[test]
fn m1_a_redaction_is_said_plainly_in_the_answer_and_recorded_as_an_allow_of_the_redacted_text() {
    let s = Service::new(probe(), Config::default());
    let r = post(
        &s,
        "a",
        "mail me at jane.doe@example.invalid please",
        "T1",
        NOW,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let b = v(&r);
    assert_eq!(b["decision"], "redact");
    assert_eq!(b["redacted"], true);
    assert!(
        b["note"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("redacted"),
        "{}",
        b["note"]
    );
    assert_eq!(
        ledger_decision(&r),
        (Decision::Allow, "within_limits".into())
    );
    // the same text at tier T0 is blocked, not redacted, and carries no redaction note
    let r0 = post(
        &s,
        "b",
        "mail me at jane.doe@example.invalid please",
        "T0",
        NOW,
    );
    let b0 = v(&r0);
    assert_eq!(b0["decision"], "block");
    assert!(b0.get("redacted").is_none() && b0.get("note").is_none());
    assert_eq!(
        ledger_decision(&r0),
        (Decision::Deny, "guard_refused".into())
    );
    // a plain allow also has neither field
    let ra = v(&post(&s, "c", "hello", "T1", NOW));
    assert_eq!(ra["decision"], "allow");
    assert!(ra.get("redacted").is_none() && ra.get("note").is_none());
}

#[test]
fn m2_the_limiter_edges_are_exact_capacity_window_end_and_retry_after() {
    let s = Service::new(
        probe(),
        Config {
            rate_capacity: 3,
            rate_window_secs: 10,
            ..Config::default()
        },
    );
    for i in 0..3 {
        assert_eq!(
            post(&s, "A", "hi", "T1", NOW).status,
            200,
            "request {i} of the capacity"
        );
    }
    let r = post(&s, "A", "hi", "T1", NOW);
    assert_eq!((r.status, r.retry_after_secs), (429, Some(10)));
    let r = post(&s, "A", "hi", "T1", NOW + 9);
    assert_eq!(
        (r.status, r.retry_after_secs),
        (429, Some(1)),
        "one second before the window ends"
    );
    assert_eq!(
        post(&s, "A", "hi", "T1", NOW + 10).status,
        200,
        "the window ends exactly at start + window"
    );
    // the new window starts at the first request after the old one ended
    for _ in 0..2 {
        assert_eq!(post(&s, "A", "hi", "T1", NOW + 10).status, 200);
    }
    let r = post(&s, "A", "hi", "T1", NOW + 10);
    assert_eq!((r.status, r.retry_after_secs), (429, Some(10)));
}

#[test]
fn m3_the_limiter_forgets_the_longest_unseen_client_first() {
    let s = Service::new(
        probe(),
        Config {
            rate_capacity: 1,
            rate_window_secs: 1000,
            max_clients: 3,
            ..Config::default()
        },
    );
    for c in ["A", "B", "C"] {
        assert_eq!(post(&s, c, "hi", "T1", NOW).status, 200);
    }
    assert_eq!(
        post(&s, "A", "hi", "T1", NOW + 1).status,
        429,
        "A is over its limit and is now the most recently seen"
    );
    assert_eq!(
        post(&s, "D", "hi", "T1", NOW + 2).status,
        200,
        "a new client pushes the longest-unseen one (B) out"
    );
    assert_eq!(s.tracked_clients(), 3);
    assert_eq!(
        post(&s, "B", "hi", "T1", NOW + 3).status,
        200,
        "B was forgotten, so it starts fresh"
    );
    assert_eq!(post(&s, "A", "hi", "T1", NOW + 4).status, 429, "A was kept");
}

#[test]
fn m4_a_limit_of_zero_clients_still_works_and_the_configured_body_limit_is_used() {
    let s = Service::new(
        probe(),
        Config {
            max_clients: 0,
            max_body: 100,
            ..Config::default()
        },
    );
    assert_eq!(post(&s, "x", "hi", "T1", NOW).status, 200);
    assert!(s.tracked_clients() <= 1);
    let ok = format!("{{\"text\":\"{}\",\"tier\":\"T1\"}}", "a".repeat(100 - 23));
    assert_eq!(ok.len(), 100);
    assert_eq!(
        s.handle(
            &HttpRequest {
                content_type: "application/json",
                client: "y",
                body: ok.as_bytes()
            },
            NOW
        )
        .status,
        200
    );
    let big = format!("{ok} ");
    assert_eq!(
        s.handle(
            &HttpRequest {
                content_type: "application/json",
                client: "z",
                body: big.as_bytes()
            },
            NOW
        )
        .status,
        413
    );
}

#[test]
fn m5_the_salt_changes_every_hash_and_the_same_salt_gives_the_same_hash() {
    let subject = |salt: &[u8]| {
        let s = Service::new(
            probe(),
            Config {
                salt: salt.to_vec(),
                ..Config::default()
            },
        );
        decode_event(
            v(&post(&s, "a", "same text", "T1", NOW))["record"]["event"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .fields
        .subject_hash
    };
    assert_eq!(subject(b"one"), subject(b"one"));
    assert_ne!(subject(b"one"), subject(b"two"));
    // the tier is part of the run id, so the same text at another tier is another record subject
    let s = Service::new(probe(), Config::default());
    let h = |t: &str| {
        decode_event(
            v(&post(&s, &format!("c{t}"), "same text", t, NOW))["record"]["event"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .fields
        .subject_hash
    };
    assert_ne!(h("T1"), h("T2"));
}

#[test]
fn m6_the_record_names_the_signer_and_the_time_the_caller_gave() {
    let s = Service::new(probe(), Config::default());
    let b = v(&post(&s, "a", "hello", "T2", NOW + 77));
    let f = decode_event(b["record"]["event"].as_str().unwrap())
        .unwrap()
        .fields;
    assert_eq!(f.ts, NOW + 77);
    assert_eq!(b["record"]["pubkey"], probe().pubkey_hex());
    assert_eq!(b["record"]["key_id"], f.key_id);
    assert_eq!(f.key_id.len(), 16);
}
