//! EG1b mutation triage, batch C: the hash-only record of a decision. Every field is compared with a value computed in the test, independently of the
//! engine: the SHA-256 of the body, the policy hash, byte counts, the number of leaves (body strings, keys, scalars, headers, attachments, and the
//! destination are one leaf each), flagged and passed counts, the destination id, and detector counts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action, Request};
use entropa_egress::policy::Tier;
use sha2::{Digest, Sha256};

fn fields(detail: &str) -> std::collections::BTreeMap<String, String> {
    detail
        .split(' ')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}
fn rec(req: &Request, t: Tier) -> (Action, entropa_egress::record::EvidenceRequest) {
    let m = Mem::new();
    let d = decide(req, &policy(), t, &conv(), &m);
    (d.action(), m.last())
}

#[test]
fn c1_a_blocked_secret_leaves_a_record_with_the_destination_the_counts_and_the_hashes() {
    let body = format!("key {SECRET} end");
    let (a, r) = rec(&text_req(&body), Tier::T1);
    assert_eq!(a, Action::Block);
    assert_eq!(
        (
            r.kind.as_str(),
            r.label.as_str(),
            r.decision.as_str(),
            r.control.as_str()
        ),
        ("egress.decision", "egress_blocked", "deny", "egress_guard")
    );
    // leaves: the body (1) and the destination (1); one is flagged
    assert_eq!((r.total, r.passed, r.flagged), (2, 1, 1));
    let f = fields(&r.detail);
    assert_eq!(f["tier"], "T1");
    assert_eq!(f["policy"], policy().hash());
    assert_eq!(f["req"], hex::encode(Sha256::digest(body.as_bytes())));
    assert_eq!(f["red"], "none");
    assert_eq!(f["dest"], "d1", "the destination id of the matching entry");
    assert_eq!(f["det"], "D1:1");
    assert!(f["views"].split(',').any(|v| v == "raw"), "{}", f["views"]);
    assert_eq!(f["bytes_in"], body.len().to_string());
    assert_eq!(f["bytes_out"], "0", "a blocked request sends nothing");
    assert!(
        r.run_id.starts_with("eg-") && r.run_id.len() == 27,
        "{}",
        r.run_id
    );
    // the record carries no text of the request
    assert!(!r.detail.contains("AKIA") && !r.detail.contains("key "));
}

#[test]
fn c2_a_block_for_size_or_malformed_input_still_names_the_destination() {
    let (a, r) = rec(&text_req(&"a ".repeat(40_000)), Tier::T1);
    assert_eq!(a, Action::Block);
    assert_eq!(r.reason, "size_limit");
    assert_eq!(fields(&r.detail)["dest"], "d1");
    let (_, r) = rec(&text_req("a\u{0}b"), Tier::T1);
    assert_eq!(r.reason, "malformed_request");
    assert_eq!(fields(&r.detail)["dest"], "d1");
    // a destination that is not on the list has none
    let mut q = text_req("hello");
    q.destination = "https://other.example.invalid/x".into();
    let (a, r) = rec(&q, Tier::T1);
    assert_eq!(
        (a, r.reason.as_str()),
        (Action::Block, "destination_denied")
    );
    assert_eq!(fields(&r.detail)["dest"], "none");
}

#[test]
fn c3_a_clean_request_counts_every_leaf_as_passed() {
    let mut q = json_req(r#"{"a":"x","b":["y",7,true]}"#);
    q.headers = vec![("x-note".into(), "hello".into())];
    let (a, r) = rec(&q, Tier::T1);
    assert_eq!(a, Action::Allow);
    // strings x, y (2) + keys a, b (2) + scalars 7, true (2) + one header (1) + the destination (1)
    assert_eq!((r.total, r.passed, r.flagged), (8, 8, 0));
    let f = fields(&r.detail);
    assert_eq!(
        (f["det"].as_str(), f["views"].as_str(), f["red"].as_str()),
        ("none", "none", "none")
    );
    assert_eq!(
        f["bytes_out"],
        q.body.len().to_string(),
        "an allowed request sends its own bytes"
    );
    assert_eq!(r.decision, "allow");
    assert_eq!(r.label, "egress_allowed");
}

#[test]
fn c4_two_secrets_in_two_fields_are_two_matches_and_a_split_secret_is_one_cross_field_match() {
    let two = json_req(&format!(r#"{{"a":"{SECRET}","b":"ASIAIOSFODNN7EXAMPLE"}}"#));
    let (_, r) = rec(&two, Tier::T1);
    assert_eq!(fields(&r.detail)["det"], "D1:2");
    assert_eq!(r.flagged, 2, "two flagged leaves");
    // a key cut across two fields is found only in the joined view: one match, one flagged unit, and no single leaf is flagged
    let split = json_req(r#"{"a":"AKIAIOSFO","b":"DNN7EXAMPLE"}"#);
    let (a, r) = rec(&split, Tier::T1);
    assert_eq!(a, Action::Block);
    assert_eq!(fields(&r.detail)["det"], "D1:1", "{}", r.detail);
    // leaves: strings 2 + keys 2 + the destination 1 = 5; the cross-field match counts once as flagged
    assert_eq!((r.total, r.flagged, r.passed), (5, 1, 4));
}

#[test]
fn c5_a_redaction_record_names_the_redacted_hash_and_the_byte_counts() {
    let body = "write to jane.doe@example.invalid now";
    let m = Mem::new();
    let d = decide(&text_req(body), &policy(), Tier::T1, &conv(), &m);
    assert_eq!(d.action(), Action::Redact);
    let r = m.last();
    let f = fields(&r.detail);
    let red = d.redacted_body().unwrap();
    assert_eq!(f["red"], hex::encode(Sha256::digest(red)));
    assert_eq!(f["bytes_out"], red.len().to_string());
    assert_eq!(f["bytes_in"], body.len().to_string());
    assert_eq!(f["det"], "D5.email:1");
    assert_eq!(r.label, "egress_redacted");
    assert_eq!(
        r.decision, "allow",
        "a redacted request is allowed out, redacted"
    );
}
