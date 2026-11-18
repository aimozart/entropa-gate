//! EG1b mutation triage, batch I: policy validation and URL parsing, through the public API only (`Policy::parse` on edited and re-signed templates, `parse_url`,
//! `allows_egress`). Rules from EG0 section 3 and the policy documentation: hosts are lower-case letters, digits, hyphens and dots, with at least one dot, labels of 1 to 63
//! characters not starting with `xn--`, not all digits, no leading or trailing dot or hyphen, at most 253 characters; a destination needs a scheme of https or http, a valid
//! host, a non-zero port and an id; every tier needs limits and a tier entry; D1 to D4 stay at block at T3, and the floor classes may not loosen toward higher tiers; T0 never
//! sends; a URL has no whitespace, control character, backslash or non-ASCII character.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::policy::{parse_url, sign_dev, template_json, DevHashVerifier, Policy, Tier};
use serde_json::{json, Value};

const KEY: &[u8] = b"dev-verifier-key-not-a-signature";

fn parse(v: &Value) -> Result<Policy, String> {
    Policy::parse(&sign_dev(&v.to_string(), KEY), &DevHashVerifier::new(KEY))
        .map_err(|e| format!("{e:?}"))
}
fn base() -> Value {
    serde_json::from_str(&template_json("api.model.example")).unwrap()
}
fn with_host(h: &str) -> Value {
    let mut v = base();
    v["destinations"][0]["host"] = json!(h);
    v
}

#[test]
fn i1_host_rules() {
    let long_label = "a".repeat(63);
    let too_long_label = "a".repeat(64);
    for ok in [
        "api.model.example",
        "a-b.example.invalid",
        "x1.example.invalid",
        "a.b",
        &format!("{long_label}.example.invalid"),
        "1a.example.invalid",
        "a.1b",
    ] {
        assert!(parse(&with_host(ok)).is_ok(), "{ok} should be a valid host");
    }
    let host253 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host253.len(), 253);
    assert!(
        parse(&with_host(&host253)).is_ok(),
        "253 characters is the limit"
    );
    let host254 = format!("{host253}e");
    assert!(parse(&with_host(&host254)).is_err(), "254 characters");
    for bad in [
        "",
        "localhost",
        "a_b.example.invalid",
        "A.example.invalid",
        "exa mple.invalid",
        ".example.invalid",
        "example.invalid.",
        "-a.example.invalid",
        "example.invalid-",
        "a..b.example.invalid",
        "xn--a.example.invalid",
        "1.2.3.4",
        "10.0.0",
        "a.example.invalid:443",
        "a.example.invalid/x",
        "é.example.invalid",
    ] {
        assert!(parse(&with_host(bad)).is_err(), "{bad:?} should be refused");
    }
    assert!(
        parse(&with_host(&format!("{too_long_label}.example.invalid"))).is_err(),
        "a 64-character label"
    );
    // a hyphen or dot alone in the host alphabet is not enough: each is accepted inside a name
    assert!(parse(&with_host("a-b-c.d-e.example.invalid")).is_ok());
}

#[test]
fn i2_destination_fields_are_all_required() {
    let mut v = base();
    v["destinations"][0]["id"] = json!("");
    assert!(parse(&v).is_err(), "an empty id");
    let mut v = base();
    v["destinations"][0]["port"] = json!(0);
    assert!(parse(&v).is_err(), "port 0");
    let mut v = base();
    v["destinations"][0]["scheme"] = json!("ftp");
    assert!(parse(&v).is_err(), "scheme ftp");
    let mut v = base();
    v["destinations"][0]["scheme"] = json!("http");
    assert!(
        parse(&v).is_ok(),
        "http is a valid scheme (the destination check decides about use)"
    );
    assert!(parse(&base()).is_ok());
}

#[test]
fn i3_every_tier_needs_limits_and_a_tier_entry() {
    for tier in ["T0", "T1", "T2", "T3"] {
        let mut v = base();
        v["limits"].as_object_mut().unwrap().remove(tier);
        assert!(parse(&v).is_err(), "no limits for {tier}");
        let mut v = base();
        v["tiers"].as_object_mut().unwrap().remove(tier);
        assert!(parse(&v).is_err(), "no tier entry for {tier}");
        let mut v = base();
        v["limits"].as_object_mut().unwrap().remove(tier);
        v["tiers"].as_object_mut().unwrap().remove(tier);
        assert!(parse(&v).is_err(), "neither for {tier}");
    }
}

#[test]
fn i4_floor_classes_never_loosen_toward_higher_tiers() {
    // D1 to D4 stay at block at T3
    for det in ["D1", "D2", "D3", "D4"] {
        let mut v = base();
        v["detectors"]["T3"][det] = json!("redact");
        assert!(parse(&v).is_err(), "{det} below block at T3");
    }
    // D5.id (a floor class) may not be looser at T2 or T3 than at T1
    let mut v = base();
    v["detectors"]["T1"]["D5.id"] = json!("block");
    v["detectors"]["T2"]["D5.id"] = json!("redact");
    assert!(parse(&v).is_err(), "T2 looser than T1");
    let mut v = base();
    v["detectors"]["T1"]["D5.id"] = json!("block");
    v["detectors"]["T3"]["D5.id"] = json!("redact");
    assert!(parse(&v).is_err(), "T3 looser than T1");
    // stricter toward higher tiers is allowed
    let mut v = base();
    v["detectors"]["T1"]["D5.id"] = json!("redact");
    v["detectors"]["T2"]["D5.id"] = json!("block");
    v["detectors"]["T3"]["D5.id"] = json!("block");
    assert!(parse(&v).is_ok(), "a stricter higher tier is fine");
    // T2 stricter than T1 and T3 equal to T1: allowed (each higher tier is compared with T1, not with the tier below)
    let mut v = base();
    v["detectors"]["T1"]["D5.id"] = json!("redact");
    v["detectors"]["T2"]["D5.id"] = json!("block");
    v["detectors"]["T3"]["D5.id"] = json!("redact");
    assert!(
        parse(&v).is_ok(),
        "the rule compares T2 and T3 with T1 only: T3 equal to T1 passes even if T2 is stricter"
    );
}

#[test]
fn i5_t0_never_sends_and_a_tier_that_says_no_does_not_send() {
    let p = parse(&base()).unwrap();
    assert!(!p.allows_egress(Tier::T0));
    for t in [Tier::T1, Tier::T2, Tier::T3] {
        assert!(p.allows_egress(t), "{t:?}");
    }
    // a policy that tries to let T0 send is still not allowed to
    let mut v = base();
    v["tiers"]["T0"]["allow_egress"] = json!(true);
    if let Ok(p) = parse(&v) {
        assert!(!p.allows_egress(Tier::T0), "T0 can never send");
    }
    // a tier whose entry says false does not send
    let mut v = base();
    v["tiers"]["T2"]["allow_egress"] = json!(false);
    let p = parse(&v).unwrap();
    assert!(!p.allows_egress(Tier::T2));
    assert!(p.allows_egress(Tier::T1) && p.allows_egress(Tier::T3));
}

#[test]
fn i6_urls_with_whitespace_control_backslash_or_non_ascii_are_refused() {
    assert!(parse_url("https://api.model.example/v1/chat").is_some());
    for bad in [
        "",
        "https://api.model.example/a b",
        "https://api.model.example/a\tb",
        "https://api.model.example/a\nb",
        "https://api.model.example/a\u{0}b",
        "https://api.model.example/a\u{7f}b",
        "https://api.model.example\\@evil.invalid",
        "https://api.model.example/a\\b",
        "https://api.model.example/\u{e9}",
        "https://\u{ff41}pi.model.example/",
    ] {
        assert!(parse_url(bad).is_none(), "{bad:?} should be refused");
    }
}
