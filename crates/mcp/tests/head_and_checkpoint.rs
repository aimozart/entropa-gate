//! Test-plan rows H1-H5 and C1-C7 (docs/ARCHITECTURE-MCP.md section 12).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use entropa_mcp::{key_id, Server};
use serde_json::json;

#[test]
fn h1_head_from_a_trusted_signer() {
    let w = world(3);
    let mut s = w.server();
    let b = ok(call(&mut s, "log_head", json!({})));
    assert_eq!(b["size"], 3);
    assert_eq!(b["root"], hex::encode(w.head.root));
    assert_eq!(b["signature_valid"], true);
    assert_eq!(b["signer_trusted"], true);
    assert_eq!(b["signer_key_id"], key_id(&w.probe.pubkey_hex()));
    assert_eq!(b["record_format_version"], 2);
    assert_eq!(b["source"], "file");
}

#[test]
fn h2_head_signed_by_an_untrusted_key() {
    let w = world(2);
    let mut s = Server::new(
        vec![Probe::spawn().pubkey_hex()],
        Some(Box::new(w.mem_source())),
    );
    let b = ok(call(&mut s, "log_head", json!({})));
    assert_eq!(b["signature_valid"], true);
    assert_eq!(b["signer_trusted"], false);
}

#[test]
fn h3_head_with_a_tampered_root() {
    let w = world(2);
    let mut src = w.mem_source();
    src.head.root[0] ^= 1;
    let mut s = Server::new(vec![w.probe.pubkey_hex()], Some(Box::new(src)));
    let b = ok(call(&mut s, "log_head", json!({})));
    assert_eq!(b["signature_valid"], false);
}

#[test]
fn h4_no_source_is_unavailable_without_leaking_paths() {
    let w = world(1);
    let mut s = w.server_no_source();
    let b = err_code(call(&mut s, "log_head", json!({})), "unavailable");
    assert!(!b["detail"].as_str().unwrap().contains('/'));
}

#[test]
fn h5_extra_argument_is_invalid() {
    let w = world(1);
    let mut s = w.server();
    err_code(
        call(&mut s, "log_head", json!({"partner": "x"})),
        "invalid_arguments",
    );
}

#[test]
fn c1_valid_checkpoint_with_a_trusted_key() {
    let w = world(3);
    let mut s = w.server();
    let b = ok(call(
        &mut s,
        "verify_checkpoint",
        json!({"checkpoint": cp_json(&w.head)}),
    ));
    assert_eq!(b["signature_valid"], true);
    assert_eq!(b["signer_trusted"], true);
    assert_eq!(b["claimed_key_id"], b["trusted_key_id"]);
    assert_eq!(
        b["digest_layout"],
        "root(32)||size(u64be)||timestamp(u64be)"
    );
    assert!(b["checks"].as_array().unwrap().len() >= 2);
}

#[test]
fn c2_tampering_each_signed_field_breaks_the_signature() {
    let w = world(3);
    let mut s = w.server();
    for field in ["root", "size", "timestamp"] {
        let mut c = cp_json(&w.head);
        match field {
            "root" => {
                let mut r = w.head.root;
                r[1] ^= 1;
                c["root"] = json!(hex::encode(r));
            }
            "size" => c["size"] = json!(w.head.size + 1),
            _ => c["timestamp"] = json!(w.head.timestamp + 1),
        }
        let b = ok(call(&mut s, "verify_checkpoint", json!({"checkpoint": c})));
        assert_eq!(b["signature_valid"], false, "tampered {field}");
    }
}

#[test]
fn c3_valid_signature_but_key_not_in_the_trust_store() {
    let w = world(1);
    let mut s = Server::new(vec![Probe::spawn().pubkey_hex()], None);
    let b = ok(call(
        &mut s,
        "verify_checkpoint",
        json!({"checkpoint": cp_json(&w.head)}),
    ));
    assert_eq!(b["signature_valid"], true);
    assert_eq!(b["signer_trusted"], false);
    assert!(b["trusted_key_id"].is_null());
}

#[test]
fn c4_an_empty_trust_store_trusts_nothing() {
    let w = world(1);
    let mut s = Server::new(vec![], None);
    let b = ok(call(
        &mut s,
        "verify_checkpoint",
        json!({"checkpoint": cp_json(&w.head)}),
    ));
    assert_eq!(b["signature_valid"], true);
    assert_eq!(b["signer_trusted"], false);
}

#[test]
fn c5_a_signature_from_another_key_or_of_the_wrong_length_is_a_result_not_an_error() {
    let w = world(1);
    let mut s = w.server();
    let mut c = cp_json(&w.head);
    c["signature"] = json!(Probe::spawn().sign_hex(b"other"));
    assert_eq!(
        ok(call(&mut s, "verify_checkpoint", json!({"checkpoint": c})))["signature_valid"],
        false
    );
    let mut c = cp_json(&w.head);
    c["signature"] = json!("abcd");
    assert_eq!(
        ok(call(&mut s, "verify_checkpoint", json!({"checkpoint": c})))["signature_valid"],
        false
    );
}

#[test]
fn c6_malformed_arguments_are_invalid_arguments() {
    let w = world(1);
    let mut s = w.server();
    let good = cp_json(&w.head);
    let mut cases = vec![
        json!({}),
        json!({"checkpoint": "x"}),
        json!({"checkpoint": good.clone(), "extra": 1}),
    ];
    for (field, bad) in [
        ("root", json!("ZZ")),
        ("root", json!("ABCDEF".repeat(11)[..64].to_string())),
        ("root", json!("abc")),
        ("size", json!("3")),
        ("size", json!(-1)),
        ("size", json!(1u64 << 60)),
        ("timestamp", json!(1.5)),
        ("signature", json!("a".repeat(6620))),
        ("proposer_pubkey", json!("zz")),
    ] {
        let mut c = good.clone();
        c[field] = bad;
        cases.push(json!({"checkpoint": c}));
    }
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("root");
    cases.push(json!({"checkpoint": missing}));
    for args in cases {
        err_code(
            call(&mut s, "verify_checkpoint", args.clone()),
            "invalid_arguments",
        );
    }
}

#[test]
fn c7_the_empty_log_checkpoint_verifies() {
    let w = world(0);
    let mut s = w.server();
    let b = ok(call(
        &mut s,
        "verify_checkpoint",
        json!({"checkpoint": cp_json(&w.head)}),
    ));
    assert_eq!(b["signature_valid"], true);
    assert_eq!(b["size"], 0);
}

#[test]
fn key_id_is_sixteen_hex_chars_of_blake3_over_the_key_bytes() {
    let k = Probe::spawn().pubkey_hex();
    let id = key_id(&k);
    assert_eq!(id.len(), 16, "key_id: not yet implemented");
    assert_eq!(
        id,
        hex::encode(&blake3::hash(&hex::decode(&k).unwrap()).as_bytes()[..8])
    );
}
