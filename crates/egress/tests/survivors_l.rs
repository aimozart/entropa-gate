//! EG1b mutation triage, batch L: matches that exist only in the cross-field (joined) view. Rules (a stage record (not published)): the joined text is the conversation tail followed by
//! every body string and attachment with no separator; a match there that lies inside one leaf, or overlaps a per-leaf hit of the SAME detector, is not a new match; any other
//! is a cross-field match: it is counted for its detector once per matching view (raw, stripped) and the whole cross-field result is one flagged unit. Leaf counts are derived by hand from the field layout of each request.
//! Equivalent (listed in the plan): the `inside` test (everything inside one leaf already overlaps that leaf's own hit) and `ranges.len() > 1` (a single leaf joined alone is
//! that leaf).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action};
use entropa_egress::policy::Tier;

fn rec(body: &str) -> (Action, entropa_egress::record::EvidenceRequest) {
    let m = Mem::new();
    let d = decide(&json_req(body), &policy(), Tier::T1, &conv(), &m);
    (d.action(), m.last())
}
fn det(r: &entropa_egress::record::EvidenceRequest) -> String {
    r.detail
        .split(' ')
        .find_map(|kv| kv.strip_prefix("det="))
        .unwrap()
        .to_string()
}

#[test]
fn l1_two_separate_split_keys_are_two_cross_field_matches() {
    let (a, r) = rec(r#"{"a":"AKIAIOSFO","b":"DNN7EXAMPLE and ASIAIOSFO","c":"DNN7EXAMPLE"}"#);
    assert_eq!(a, Action::Block);
    // strings 3 + keys 3 + destination 1 = 7 leaves; no single leaf matches. The cross-field count is per matching VIEW (the raw and the stripped view of the same
    // joined text each report it), so it is at least the two keys and not exactly two; the whole cross-field result is ONE flagged unit
    let n: u32 = det(&r).strip_prefix("D1:").unwrap().parse().unwrap();
    assert!(n >= 2, "{}", r.detail);
    assert_eq!((r.total, r.flagged, r.passed), (7, 1, 6));
}

#[test]
fn l2_a_whole_key_in_one_field_and_a_split_key_in_two_others_are_two_matches() {
    let (a, r) = rec(r#"{"a":"ASIAIOSFODNN7EXAMPLE","b":"AKIAIOSFO","c":"DNN7EXAMPLE"}"#);
    assert_eq!(a, Action::Block);
    assert_eq!(det(&r), "D1:2", "{}", r.detail);
    // leaves 7; field a flagged by itself, and the cross-field match is one more flagged unit
    assert_eq!((r.total, r.flagged, r.passed), (7, 2, 5));
}

#[test]
fn l3_an_overlapping_hit_of_another_detector_does_not_hide_a_cross_field_match() {
    // an email in field a (D5.email, redact mode) and a key split across b and c: the key must still be found as D1 and the request blocked
    let (a, r) = rec(r#"{"a":"mail jane.doe@example.invalid","b":"AKIAIOSFO","c":"DNN7EXAMPLE"}"#);
    assert_eq!(a, Action::Block, "{}", r.detail);
    let d = det(&r);
    assert!(d.contains("D1:1") && d.contains("D5.email:1"), "{d}");
}

#[test]
fn l4_a_request_with_one_leaf_has_no_cross_field_match() {
    let (a, r) = rec(r#"{"a":"AKIAIOSFODNN7EXAMPLE"}"#);
    assert_eq!(a, Action::Block);
    assert_eq!(det(&r), "D1:1", "one match, not two: {}", r.detail);
    assert_eq!((r.total, r.flagged), (3, 1), "string, key, destination");
}
