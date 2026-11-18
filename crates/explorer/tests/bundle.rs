//! The explorer reads the S7c static bundle read-only and refuses anything that does not verify.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::json;

fn refuses(name: &str, text: &str) {
    match Explorer::from_bundle(text, Limits::default()) {
        Err(ExplorerError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(_) => {}
        Ok(_) => panic!("{name}: a bundle that does not verify was accepted"),
    }
}

#[test]
fn b1_the_fixture_loads() {
    let e = explorer();
    assert_eq!(e.tracked_clients(), 0);
}

#[test]
fn b2_tampered_bundles_are_refused_on_load() {
    let mut v = fixture();
    v["records"][3]["record_hex"] = json!("00".repeat(8));
    refuses("record", &v.to_string());
    let mut v = fixture();
    v["head"]["root"] = json!("ab".repeat(32));
    refuses("root", &v.to_string());
    let mut v = fixture();
    v["records"][0]["handle"] = json!("spock");
    refuses("internal name", &v.to_string());
    let mut v = fixture();
    v["extra"] = json!(1);
    refuses("extra field", &v.to_string());
    for bad in ["", "{", "[]", "null"] {
        refuses(bad, bad);
    }
}

#[test]
fn b3_an_oversized_bundle_is_refused_before_parsing() {
    let huge = format!(
        "{{\"pad\":\"{}\"}}",
        "x".repeat(entropa_ledger::MAX_BUNDLE_BYTES)
    );
    refuses("huge", &huge);
}
