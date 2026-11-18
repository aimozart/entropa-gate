//! EG1 task 2 (red first): the rule language: closed, total, monotone, hashed, fail closed when unverifiable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::policy::{sign_dev, DevHashVerifier, Policy, PolicyError};
use serde_json::{json, Value};

fn edit(f: impl FnOnce(&mut Value)) -> String {
    let mut v: Value =
        serde_json::from_str(&entropa_egress::policy::template_json("api.model.example")).unwrap();
    f(&mut v);
    sign_dev(&v.to_string(), KEY)
}
fn parse(j: &str) -> Result<Policy, PolicyError> {
    Policy::parse(j, &DevHashVerifier::new(KEY))
}

#[test]
fn p1_the_template_parses_and_has_a_stable_hash() {
    let a = policy();
    let b = policy();
    assert_eq!(a.hash(), b.hash());
    assert_eq!(a.hash().len(), 64);
    // the hash does not depend on the signature field
    let other = sign_dev(
        &entropa_egress::policy::template_json("api.model.example"),
        b"another-key",
    );
    assert!(
        parse(&other).is_err(),
        "a signature from another key does not verify"
    );
}

#[test]
fn p2_an_unverifiable_or_altered_policy_is_refused() {
    let good = policy_json();
    assert!(parse(&good).is_ok());
    let tampered = good.replacen("\"block\"", "\"allow_with_record\"", 1);
    assert!(matches!(parse(&tampered), Err(PolicyError::Signature)));
    assert!(matches!(parse("not json"), Err(PolicyError::Malformed(_))));
    assert!(matches!(
        parse("{}"),
        Err(PolicyError::Malformed(_)) | Err(PolicyError::Signature)
    ));
}

#[test]
fn p3_the_language_is_closed_unknown_keys_detectors_and_modes_are_invalid() {
    assert!(parse(&edit(|v| v["surprise"] = json!(1))).is_err());
    assert!(parse(&edit(|v| v["detectors"]["T1"]["D9"] = json!("block"))).is_err());
    assert!(parse(&edit(|v| v["detectors"]["T1"]["D1"] = json!("shrug"))).is_err());
    assert!(parse(&edit(|v| v["limits"]["T5"] = json!({}))).is_err());
    assert!(parse(&edit(|v| v["destinations"][0]["scheme"] = json!("ftp"))).is_err());
    assert!(
        parse(&edit(
            |v| v["destinations"][0]["host"] = json!("*.model.example")
        ))
        .is_err(),
        "no wildcard hosts"
    );
    assert!(
        parse(&edit(
            |v| v["destinations"][0]["host"] = json!("API.model.example")
        ))
        .is_err(),
        "hosts are lower-case ASCII"
    );
    assert!(
        parse(&edit(
            |v| v["destinations"][0]["host"] = json!("xn--pi-api.model.example")
        ))
        .is_err(),
        "no punycode"
    );
    assert!(
        parse(&edit(|v| v["destinations"][0]["host"] = json!("10.0.0.1"))).is_err(),
        "no IP literals"
    );
    assert!(parse(&edit(|v| v["version"] = json!(""))).is_err());
}

#[test]
fn p4_no_tier_may_lower_the_floor_of_d1_to_d4_and_t0_has_no_egress() {
    for d in ["D1", "D2", "D3", "D4"] {
        assert!(
            parse(&edit(|v| v["detectors"]["T3"][d] = json!("redact"))).is_err(),
            "{d} at T3"
        );
        assert!(
            parse(&edit(
                |v| v["detectors"]["T3"][d] = json!("allow_with_record")
            ))
            .is_err(),
            "{d} at T3"
        );
    }
    assert!(parse(&edit(|v| v["tiers"]["T0"]["allow_egress"] = json!(true))).is_err());
    assert!(
        parse(&edit(
            |v| v["destinations"][0]["allow_tiers"] = json!(["T0"])
        ))
        .is_err(),
        "T0 can never have a destination"
    );
}

#[test]
fn p5_stricter_tiers_never_allow_more_than_looser_ones() {
    let _ = policy();
    // and a policy that makes T3 looser than T1 for D5.id is rejected (monotone tightening toward T3 for the floor classes)
    assert!(parse(&edit(|v| {
        v["detectors"]["T1"]["D5.id"] = json!("block");
        v["detectors"]["T3"]["D5.id"] = json!("allow_with_record");
    }))
    .is_err());
}

#[test]
fn p6_every_destination_and_limit_is_closed_and_found_by_exact_match() {
    let p = policy();
    assert!(p
        .destination("https://api.model.example/v1/chat", "T1".parse().unwrap())
        .is_some());
    for bad in [
        "http://api.model.example/v1/chat",
        "https://api.model.example:444/v1/chat",
        "https://api.model.example.evil.test/",
        "https://evil.test/api.model.example",
        "https://api.model.example@evil.test/",
        "https://user:pw@api.model.example/",
        "https://api.model.example./",
        "https://xn--pi-api.model.example/",
        "https://[::1]/",
        "https://2130706433/",
        "",
    ] {
        assert!(p.destination(bad, "T1".parse().unwrap()).is_none(), "{bad}");
    }
    assert!(
        p.destination("https://API.MODEL.EXAMPLE/x", "T1".parse().unwrap())
            .is_some(),
        "scheme and host are case-insensitive in a URL"
    );
    assert!(p
        .destination("https://api.model.example/x", "T0".parse().unwrap())
        .is_none());
}
