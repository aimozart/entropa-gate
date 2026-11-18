//! H1.3 regression tests for violations found by the tamper properties (h13_tamper.rs).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_ledger::verify_bundle;
use serde_json::{json, Value};

fn base() -> Value {
    serde_json::from_str(&run_mem(7, 3).3).unwrap()
}
fn verifies(v: &Value) -> bool {
    verify_bundle(&serde_json::to_string(v).unwrap()).is_ok()
}
fn keyless_and_keyed(v: &Value) -> (usize, usize) {
    let a = v["actors"].as_array().unwrap();
    (
        a.iter()
            .position(|x| x["pubkey_hex"] == json!(""))
            .expect("a keyless actor"),
        a.iter()
            .position(|x| x["pubkey_hex"] != json!(""))
            .expect("a keyed actor"),
    )
}

/// H13-V6 (I5): the actor table's descriptive fields were never looked at, so any junk verified (null, numbers, arrays, unknown codes).
#[test]
fn w1_junk_in_the_actor_table_is_refused() {
    let v0 = base();
    assert!(verifies(&v0), "the untouched bundle verifies");
    let n = v0["actors"].as_array().unwrap().len();
    for i in 0..n {
        for field in ["role", "status", "attested_by", "may_approve"] {
            for junk in [
                json!(null),
                json!(7),
                json!("x"),
                json!([]),
                json!({}),
                json!(true),
            ] {
                // null is a valid attester (no attester): swapping it in is a valid-looking swap, the documented limit of w3
                if v0["actors"][i][field] == junk
                    || (field == "attested_by" && junk.is_null())
                    || (field == "may_approve" && junk == json!([]))
                {
                    continue;
                }
                let mut v = v0.clone();
                v["actors"][i][field] = junk.clone();
                assert!(!verifies(&v), "actors[{i}].{field} = {junk} verified");
            }
        }
        let mut v = v0.clone();
        v["actors"][i]["may_approve"] = json!(["not-an-action-class"]);
        assert!(
            !verifies(&v),
            "actors[{i}].may_approve with an unknown class verified"
        );
    }
}

/// H13-V6 (I5): the status must agree with the key: no key is keyless, a key is active or revoked.
#[test]
fn w2_a_status_that_contradicts_the_key_is_refused() {
    let v0 = base();
    let (kl, kd) = keyless_and_keyed(&v0);
    let mut v = v0.clone();
    v["actors"][kl]["status"] = json!("active");
    assert!(!verifies(&v), "a keyless actor shown active");
    let mut v = v0.clone();
    v["actors"][kd]["status"] = json!("keyless");
    assert!(!verifies(&v), "a keyed actor shown keyless");
}

/// A documented limit, kept visible: the actor table's role, may_approve and attested_by are PRESENTATION. Swapping one valid value for
/// another valid value still verifies, because the verifier checks signatures, not the directory's attributes. If this test ever fails the
/// limit has been fixed: delete it and say so in a stage record (not published).
#[test]
fn w3_known_limit_a_valid_looking_swap_of_a_role_is_not_detected() {
    let mut v = base();
    let (_, kd) = keyless_and_keyed(&v);
    let was = v["actors"][kd]["role"].clone();
    v["actors"][kd]["role"] = if was == json!("ai") {
        json!("human")
    } else {
        json!("ai")
    };
    assert!(
        verifies(&v),
        "known limit: presentation fields are not authenticated"
    );
}

/// H13-V7 (I5): JSON with a DUPLICATED key. serde_json keeps the last value, the signature is checked on that value, and a reader that keeps the
/// first value sees a forged one. A witness statement or a bundle with a duplicated key must not verify.
#[test]
fn w4_a_witness_statement_with_a_duplicated_key_is_refused() {
    let v0 = base();
    assert!(verifies(&v0));
    let s = v0["witnesses"][0].as_str().unwrap().to_string();
    let forged = format!("{{\"previous_root\":\"{}\",{}", "ab".repeat(32), &s[1..]);
    assert_ne!(forged, s);
    let mut v = v0.clone();
    v["witnesses"][0] = json!(forged);
    assert!(
        !verifies(&v),
        "a witness statement with a forged first previous_root verified"
    );
}

#[test]
fn w5_a_bundle_with_a_duplicated_top_level_key_is_refused() {
    let text = run_mem(7, 3).3;
    assert!(verify_bundle(&text).is_ok());
    // a forged first occurrence of "v" and of "synthetic"; the real ones come later and win in serde_json
    let forged = format!("{{\"v\":2,\"synthetic\":false,{}", &text[1..]);
    assert!(
        verify_bundle(&forged).is_err(),
        "a bundle with duplicated keys verified"
    );
    // a duplicated key deeper down: the head
    let i = text.find("\"head\":{").unwrap() + "\"head\":{".len();
    let deeper = format!("{}\"size\":999999,{}", &text[..i], &text[i..]);
    assert!(
        verify_bundle(&deeper).is_err(),
        "a bundle with a duplicated nested key verified"
    );
}
