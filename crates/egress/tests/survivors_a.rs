//! EG1b mutation triage, batch A: the small public surface that no test read (`as_str` tables, `Policy::version`, `Decision::detectors` and `views`) and
//! `to_value`, which rebuilds a redacted JSON body. Expected values are written from the documentation of each item, not from the code.
//! Equivalent mutants of this batch (argued in a stage record (not published)): `V::expecting` (a serde error message that is discarded: the error is mapped to a
//! closed reason by its prefix only) and `_use` (dead code kept to use an import; it is never called).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action};
use entropa_egress::detect::{Det, ViewKind};
use entropa_egress::policy::Tier;

#[test]
fn a1_wire_ids_are_the_documented_words() {
    assert_eq!(ViewKind::Raw.as_str(), "raw");
    assert_eq!(ViewKind::Folded.as_str(), "folded");
    assert_eq!(ViewKind::Stripped.as_str(), "stripped");
    assert_eq!(ViewKind::Decoded.as_str(), "decoded");
    assert_eq!(ViewKind::Obfuscated.as_str(), "decoded", "an obfuscated (rot13 or reversed) token is reported as decoded: the wire vocabulary has four ids");
    assert_eq!(
        [Tier::T0, Tier::T1, Tier::T2, Tier::T3].map(Tier::as_str),
        ["T0", "T1", "T2", "T3"]
    );
    assert_eq!(policy().version(), "1", "the template policy is version 1");
}

#[test]
fn a2_a_decision_reports_the_detectors_and_the_views_that_matched() {
    let d = decide(
        &text_req(&format!("key {SECRET} end")),
        &policy(),
        Tier::T1,
        &conv(),
        &Mem::new(),
    );
    assert_eq!(d.action(), Action::Block);
    assert_eq!(
        d.detectors().get(&Det::D1),
        Some(&1),
        "one D1 match: {:?}",
        d.detectors()
    );
    assert!(
        d.views().contains(&ViewKind::Raw),
        "the raw view matched: {:?}",
        d.views()
    );
    // a clean request reports nothing
    let c = decide(
        &text_req("hello"),
        &policy(),
        Tier::T1,
        &conv(),
        &Mem::new(),
    );
    assert!(c.detectors().is_empty() && c.views().is_empty());
    // two different keys give a count of two for the same detector
    let two = decide(
        &text_req(&format!("{SECRET} and ASIAIOSFODNN7EXAMPLE")),
        &policy(),
        Tier::T1,
        &conv(),
        &Mem::new(),
    );
    assert_eq!(
        two.detectors().get(&Det::D1),
        Some(&2),
        "{:?}",
        two.detectors()
    );
}

#[test]
fn a3_a_redacted_json_body_keeps_its_structure_and_its_other_values() {
    let body =
        r#"{"a":{"b":["x","write to jane.doe@example.invalid now"],"n":5},"t":true,"z":null}"#;
    let d = decide(&json_req(body), &policy(), Tier::T1, &conv(), &Mem::new());
    assert_eq!(d.action(), Action::Redact, "{:?}", d.reason());
    let red: serde_json::Value =
        serde_json::from_slice(d.redacted_body().expect("a redacted body")).unwrap();
    assert_eq!(red["a"]["b"][0], "x");
    assert_eq!(red["a"]["n"], 5);
    assert_eq!(red["t"], true);
    assert!(red["z"].is_null());
    let s = red["a"]["b"][1].as_str().unwrap();
    assert!(
        !s.contains("jane.doe") && s.starts_with("write to ") && s.ends_with(" now"),
        "{s}"
    );
    assert_eq!(red.as_object().unwrap().len(), 3);
    assert_eq!(red["a"].as_object().unwrap().len(), 2);
    assert_eq!(red["a"]["b"].as_array().unwrap().len(), 2);
}
