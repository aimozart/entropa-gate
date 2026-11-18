//! S2e: tests written to kill the mutants that survived the first cargo-mutants run on entropa-mcp
//! (docs/evidence/s2e-mutants-first-run.txt). Each test names the behavior it pins.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_mcp::{Config, Server};
use serde_json::{json, Value};

fn check_named(body: &Value, name: &str) -> bool {
    body["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()["passed"]
        .as_bool()
        .unwrap()
}

#[test]
fn size_and_timestamp_accept_2_pow_53_minus_1_and_reject_2_pow_53() {
    let w = world(1);
    let mut s = w.server_no_source();
    let mut c = cp_json(&w.head);
    c["size"] = json!(9_007_199_254_740_991u64);
    assert!(!call(&mut s, "verify_checkpoint", json!({"checkpoint": c})).is_error);
    let mut c = cp_json(&w.head);
    c["size"] = json!(9_007_199_254_740_992u64);
    err_code(
        call(&mut s, "verify_checkpoint", json!({"checkpoint": c})),
        "invalid_arguments",
    );
}

#[test]
fn the_trusted_key_list_accepts_exactly_eight_keys_and_rejects_nine() {
    let k = entropa_core::Probe::spawn().pubkey_hex();
    let list = |n: usize| vec![k.clone(); n].join(",");
    assert_eq!(
        Config::from_vars(|n| (n == "ENTROPA_TRUSTED_PUBKEYS").then(|| list(8)))
            .unwrap()
            .trusted_pubkeys
            .len(),
        8
    );
    assert!(Config::from_vars(|n| (n == "ENTROPA_TRUSTED_PUBKEYS").then(|| list(9))).is_err());
}

#[test]
fn previews_cut_at_exactly_128_characters() {
    let mut log = entropa_core::transparency_log::TransparencyLog::new();
    let probe = entropa_core::Probe::spawn();
    for len in [127usize, 128, 129] {
        log.append(&entropa_core::transparency_log::encode_record(&"é".repeat(len), None).unwrap());
    }
    let head = log.checkpoint(&probe, 1);
    let mut s = Server::new(vec![probe.pubkey_hex()], None);
    let expect = [(127, false), (128, false), (129, true)];
    for (i, (len, truncated)) in expect.iter().enumerate() {
        let b = ok(call_at(
            &mut s,
            "verify_receipt",
            json!({"receipt": receipt_json(&log.receipt(i, &head).unwrap())}),
            T0 + i as u64 * 7_000,
        ));
        assert_eq!(b["record"]["payload_truncated"], *truncated, "len {len}");
        assert_eq!(
            b["record"]["payload_preview"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            (*len).min(128)
        );
    }
}

#[test]
fn index_in_range_check_is_true_below_the_size_and_false_at_it() {
    let w = world(4);
    let mut s = w.server_no_source();
    let mut r = receipt_json(&w.receipt(3));
    assert!(check_named(
        &ok(call(
            &mut s,
            "verify_receipt",
            json!({"receipt": r.clone()})
        )),
        "index_in_range"
    ));
    r["index"] = json!(4);
    assert!(!check_named(
        &ok(call_at(
            &mut s,
            "verify_receipt",
            json!({"receipt": r}),
            T0 + 5_000
        )),
        "index_in_range"
    ));
}

#[test]
fn valid_needs_all_three_signature_trust_and_inclusion() {
    let w = world(3);
    // signature + inclusion ok, untrusted: not valid
    let mut s = Server::new(vec![], None);
    let b = ok(call(
        &mut s,
        "verify_receipt",
        json!({"receipt": receipt_json(&w.receipt(1))}),
    ));
    assert_eq!(
        (
            b["signature_valid"].as_bool(),
            b["inclusion_valid"].as_bool(),
            b["valid"].as_bool()
        ),
        (Some(true), Some(true), Some(false))
    );
    // signature + trust ok, inclusion bad: not valid
    let mut s = w.server_no_source();
    let mut r = receipt_json(&w.receipt(1));
    r["record"] = json!("00");
    let b = ok(call(&mut s, "verify_receipt", json!({"receipt": r})));
    assert_eq!(
        (
            b["signer_trusted"].as_bool(),
            b["inclusion_valid"].as_bool(),
            b["valid"].as_bool()
        ),
        (Some(true), Some(false), Some(false))
    );
}

#[test]
fn matches_current_head_needs_both_the_same_root_and_the_same_size() {
    let w = world(4);
    let mut s = w.server();
    let mut same_root_other_size = receipt_json(&w.receipt(1));
    same_root_other_size["checkpoint"]["size"] = json!(5);
    assert_eq!(
        ok(call(
            &mut s,
            "verify_receipt",
            json!({"receipt": same_root_other_size})
        ))["matches_current_head"],
        false
    );
    let mut other_root_same_size = receipt_json(&w.receipt(1));
    other_root_same_size["checkpoint"]["root"] = json!(hex::encode([7u8; 32]));
    assert_eq!(
        ok(call_at(
            &mut s,
            "verify_receipt",
            json!({"receipt": other_root_same_size}),
            T0 + 5_000
        ))["matches_current_head"],
        false
    );
}

#[test]
fn explain_names_the_short_leaf_hash_and_flags_a_path_that_does_not_fit_the_index() {
    let w = world(4);
    let mut s = w.server_no_source();
    let r = w.receipt(1);
    let leaf = hex::encode(entropa_core::merkle::leaf_hash(&r.record));
    let b = ok(call(
        &mut s,
        "explain_proof",
        json!({"receipt": receipt_json(&r)}),
    ));
    assert!(
        b["narrative"].as_str().unwrap().contains(&leaf[..8]),
        "narrative must show the short leaf hash"
    );
    assert!(!b["narrative"].as_str().unwrap().contains("does not fit"));
    // hashes still combine to the root, but the claimed index is wrong
    let mut wrong = receipt_json(&r);
    wrong["index"] = json!(2);
    let b = ok(call_at(
        &mut s,
        "explain_proof",
        json!({"receipt": wrong}),
        T0 + 5_000,
    ));
    assert_eq!(b["root_matches"], true);
    assert!(b["narrative"].as_str().unwrap().contains("does not fit"));
}

#[test]
fn explain_marks_left_and_right_steps_and_caps_the_narrative() {
    let w = world(8);
    let mut s = w.server_no_source();
    let b = ok(call(
        &mut s,
        "explain_proof",
        json!({"receipt": receipt_json(&w.receipt(2))}),
    ));
    let sides: Vec<_> = b["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["operation"] == "combine")
        .map(|x| x["side"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(sides, vec!["Right", "Left", "Right"]); // index 2 of 8: sibling 3 right, pair (0,1) left, half (4..8) right
    let mut c = receipt_json(&w.receipt(0));
    c["proof"] = json!(vec![
        json!({"sibling": hex::encode([1u8; 32]), "side": "Left"});
        64
    ]);
    let long = ok(call_at(
        &mut s,
        "explain_proof",
        json!({"receipt": c}),
        T0 + 5_000,
    ));
    let n = long["narrative"].as_str().unwrap();
    assert!(n.len() <= 4000);
    assert!(
        n.contains("Root mismatch"),
        "the conclusion must survive the cap"
    );
}

#[test]
fn log_head_names_its_source_kind_for_a_real_file_source() {
    let w = world(2);
    let export = json!({"checkpoint": cp_json(&w.head), "records": (0..2).map(|i| hex::encode(w.receipt(i).record)).collect::<Vec<_>>()});
    let src = entropa_mcp::FileSource::from_json(&export.to_string()).unwrap();
    let mut s = Server::new(vec![w.probe.pubkey_hex()], Some(Box::new(src)));
    assert_eq!(ok(call(&mut s, "log_head", json!({})))["source"], "file");
}

#[test]
fn the_tool_schemas_carry_the_documented_limits() {
    let tools = Server::tools();
    let vr = tools.iter().find(|t| t.name == "verify_receipt").unwrap();
    let receipt = &vr.input_schema["properties"]["receipt"];
    assert_eq!(receipt["properties"]["proof"]["maxItems"], 64);
    assert_eq!(receipt["properties"]["record"]["maxLength"], 131_072);
    assert_eq!(
        receipt["properties"]["checkpoint"]["properties"]["signature"]["maxLength"],
        6618
    );
    assert_eq!(
        receipt["properties"]["checkpoint"]["properties"]["root"]["pattern"],
        "^[0-9a-f]{64}$"
    );
    assert_eq!(receipt["additionalProperties"], false);
}

#[test]
fn max_line_bytes_is_one_mebibyte() {
    assert_eq!(entropa_mcp::MAX_LINE_BYTES, 1024 * 1024);
}

#[test]
fn explain_narrative_walks_every_step_for_a_normal_proof() {
    let w = world(8);
    let mut s = w.server_no_source();
    let b = ok(call(
        &mut s,
        "explain_proof",
        json!({"receipt": receipt_json(&w.receipt(2))}),
    ));
    let n = b["narrative"].as_str().unwrap();
    assert!(
        n.contains("Combine with the right sibling") && n.contains("Combine with the left sibling"),
        "{n}"
    );
    assert!(n.contains("equals the checkpoint root"));
}
