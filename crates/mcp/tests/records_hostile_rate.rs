//! Test-plan rows L1-L6, X1-X3, Q1-Q3, N4 and config/FileSource rows.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::transparency_log::encode_record;
use entropa_mcp::{Config, FileSource, LogSource, Server, TOOL_NAMES};
use proptest::prelude::*;
use serde_json::{json, Value};

#[test]
fn l1_default_limit_lists_oldest_first() {
    let w = world(5);
    let mut s = w.server();
    let b = ok(call(&mut s, "list_records", json!({})));
    let recs = b["records"].as_array().unwrap();
    assert_eq!(recs.len(), 5);
    assert_eq!(b["total"], 5);
    assert!(b["next_since_index"].is_null());
    for (i, r) in recs.iter().enumerate() {
        assert_eq!(r["index"], i);
        assert_eq!(r["preview"]["payload_preview"], format!("event-{i}"));
        assert_eq!(r["preview"]["untrusted_text"], true);
    }
}

#[test]
fn l2_pages_are_disjoint_and_cover_the_log() {
    let w = world(5);
    let mut s = w.server();
    let mut seen = vec![];
    let mut since = json!(0);
    for step in 0..5 {
        let b = ok(call_at(
            &mut s,
            "list_records",
            json!({"limit": 2, "since_index": since}),
            T0 + step * 10_000,
        ));
        for r in b["records"].as_array().unwrap() {
            seen.push(r["index"].as_u64().unwrap());
        }
        if b["next_since_index"].is_null() {
            break;
        }
        since = b["next_since_index"].clone();
    }
    assert_eq!(seen, vec![0, 1, 2, 3, 4]);
}

#[test]
fn l3_out_of_range_arguments_are_rejected_not_clamped() {
    let w = world(3);
    let mut s = w.server();
    for (i, args) in [
        json!({"limit": 0}),
        json!({"limit": 101}),
        json!({"limit": -1}),
        json!({"limit": 1.5}),
        json!({"limit": "3"}),
        json!({"since_index": -1}),
        json!({"extra": 1}),
    ]
    .into_iter()
    .enumerate()
    {
        err_code(
            call_at(&mut s, "list_records", args, T0 + i as u64 * 7_000),
            "invalid_arguments",
        );
    }
}

#[test]
fn l4_since_index_beyond_the_log_is_an_empty_list() {
    let w = world(3);
    let mut s = w.server();
    let b = ok(call(&mut s, "list_records", json!({"since_index": 99})));
    assert_eq!(b["records"].as_array().unwrap().len(), 0);
}

#[test]
fn l5_a_large_payload_is_only_previewed() {
    let mut log = entropa_core::transparency_log::TransparencyLog::new();
    log.append(&encode_record(&"p".repeat(10_000), None).unwrap());
    let probe = entropa_core::Probe::spawn();
    let head = log.checkpoint(&probe, 1);
    let rec = log.receipt(0, &head).unwrap().record;
    let src = MemSource {
        head,
        records: vec![rec],
    };
    let mut s = Server::new(vec![probe.pubkey_hex()], Some(Box::new(src)));
    let out = call(&mut s, "list_records", json!({}));
    assert_eq!(out.body["records"][0]["preview"]["payload_truncated"], true);
    assert!(serde_json::to_vec(&out.body).unwrap().len() <= 64 * 1024);
}

#[test]
fn l6_no_source_is_unavailable() {
    let w = world(1);
    let mut s = w.server_no_source();
    err_code(call(&mut s, "list_records", json!({})), "unavailable");
}

#[test]
fn x1_hostile_strings_are_treated_as_data() {
    let w = world(1);
    let mut s = w.server_no_source();
    let hostile = [
        "https://evil.example/x",
        "../../etc/passwd",
        "$(rm -rf /)",
        "900-00-0001", // reserved-invalid SSN shape (P0): same hostile-string role, can never match a real person
        "\u{0}\u{0}",
        "' OR 1=1 --",
    ];
    for (i, h) in hostile.iter().enumerate() {
        let mut c = cp_json(&w.head);
        c["root"] = json!(h);
        let out = call_at(
            &mut s,
            "verify_checkpoint",
            json!({"checkpoint": c}),
            T0 + i as u64 * 3_000,
        );
        assert!(out.is_error && out.body["error"] == "invalid_arguments");
        assert!(
            !out.body.to_string().contains(h),
            "the offending value must not be echoed"
        );
    }
}

#[test]
fn x2_unknown_tools_and_non_object_arguments_do_not_panic() {
    let w = world(1);
    let mut s = w.server_no_source();
    for (i, args) in [
        json!(null),
        json!([]),
        json!("x"),
        json!(1),
        json!({"a": {"b": {"c": {"d": {"e": 1}}}}}),
    ]
    .into_iter()
    .enumerate()
    {
        for tool in TOOL_NAMES {
            let out = s.call_at(tool, &args, T0 + (i as u64 * 5 + 1) * 60_000);
            assert!(!out.is_not_implemented(), "{tool}: not yet implemented");
            assert!(out.is_error, "{tool} {args}");
        }
    }
    let out = s.call_at("no_such_tool", &json!({}), T0);
    assert!(
        !out.is_not_implemented(),
        "no_such_tool: not yet implemented"
    );
    assert!(out.is_error);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    /// X3: garbage arguments never panic and always yield a well-formed outcome.
    #[test]
    fn x3_random_json_never_panics(s_val in "[ -~]{0,40}", n in any::<i64>(), tool_idx in 0usize..5, nested in any::<bool>()) {
        let w = world(1);
        let mut srv = w.server();
        let args = if nested { json!({"receipt": {"index": n, "record": s_val, "proof": [s_val], "checkpoint": {"size": n}}}) } else { json!({"checkpoint": s_val, "limit": n}) };
        let out = srv.call_at(TOOL_NAMES[tool_idx], &args, T0);
        prop_assert!(!out.is_not_implemented(), "not yet implemented");
        prop_assert!(out.body.is_object());
    }
}

#[test]
fn q1_the_31st_call_in_a_minute_is_rate_limited() {
    let w = world(1);
    let mut s = w.server_no_source();
    for i in 0..30 {
        let out = call_at(
            &mut s,
            "verify_checkpoint",
            json!({"checkpoint": cp_json(&w.head)}),
            T0 + i * 100,
        );
        assert_ne!(out.body["error"], "rate_limited", "call {i}");
    }
    let b = err_code(
        call_at(
            &mut s,
            "verify_checkpoint",
            json!({"checkpoint": cp_json(&w.head)}),
            T0 + 3_000,
        ),
        "rate_limited",
    );
    assert_eq!(b["limit"], "overall");
    assert!(b["retry_after_seconds"].as_u64().unwrap() >= 1);
}

#[test]
fn q2_the_11th_list_records_call_is_limited_separately() {
    let w = world(2);
    let mut s = w.server();
    for i in 0..10 {
        assert!(
            !call_at(&mut s, "list_records", json!({}), T0 + i * 100).is_error,
            "call {i}"
        );
    }
    let b = err_code(
        call_at(&mut s, "list_records", json!({}), T0 + 2_000),
        "rate_limited",
    );
    assert_eq!(b["limit"], "list_records");
}

#[test]
fn q3_the_window_slides_and_refused_calls_do_not_extend_it() {
    let w = world(1);
    let mut s = w.server_no_source();
    let args = json!({"checkpoint": cp_json(&w.head)});
    for _ in 0..30 {
        call_at(&mut s, "verify_checkpoint", args.clone(), T0);
    }
    err_code(
        call_at(&mut s, "verify_checkpoint", args.clone(), T0 + 30_000),
        "rate_limited",
    );
    assert!(!call_at(&mut s, "verify_checkpoint", args, T0 + 60_000).is_error);
}

#[test]
fn n4_tool_catalogue_has_fixed_order_schemas_and_the_honesty_statements() {
    let tools = Server::tools();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        TOOL_NAMES.to_vec(),
        "tool catalogue: not yet implemented"
    );
    for t in &tools {
        assert!(t
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'));
        assert!(t.input_schema.is_object() && t.output_schema.is_object());
    }
    let vr = tools.iter().find(|t| t.name == "verify_receipt").unwrap();
    assert!(vr
        .description
        .contains("does not prove the decision was correct"));
    assert!(vr.description.contains("bound to the proof"));
    assert!(vr.description.contains("signature"));
}

#[test]
fn cfg_config_reads_only_keys_and_a_log_location() {
    let k = entropa_core::Probe::spawn().pubkey_hex();
    let get = |name: &str| match name {
        "ENTROPA_TRUSTED_PUBKEYS" => Some(format!("{k},{k}")),
        "ENTROPA_LOG_FILE" => Some("/data/log.json".to_string()),
        _ => None,
    };
    let c = Config::from_vars(get).unwrap();
    assert_eq!(c.trusted_pubkeys.len(), 2);
    assert_eq!(c.log_file.as_deref(), Some("/data/log.json"));
    assert!(Config::from_vars(|_| None)
        .unwrap()
        .trusted_pubkeys
        .is_empty());
    let too_many = vec![k.clone(); 9].join(",");
    assert!(
        Config::from_vars(|n| (n == "ENTROPA_TRUSTED_PUBKEYS").then(|| too_many.clone())).is_err()
    );
    assert!(
        Config::from_vars(|n| (n == "ENTROPA_TRUSTED_PUBKEYS").then(|| "not-hex".to_string()))
            .is_err()
    );
    assert!(
        Config::from_vars(|n| (n == "ENTROPA_TRUSTED_PUBKEYS").then(|| k.to_uppercase())).is_err()
    );
}

#[test]
fn src_file_source_round_trips_an_exported_log() {
    let w = world(3);
    let export = json!({
        "checkpoint": cp_json(&w.head),
        "records": (0..3).map(|i| hex::encode(w.receipt(i).record)).collect::<Vec<_>>(),
    });
    let src = FileSource::from_json(&export.to_string()).expect("file source: not yet implemented");
    assert_eq!(src.head().unwrap(), w.head);
    let rows = src.read(1, 5).unwrap();
    assert_eq!(rows.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![1, 2]);
    assert!(FileSource::from_json("not json").is_err());
    let bad: Value = json!({"checkpoint": cp_json(&w.head), "records": ["zz"]});
    assert!(FileSource::from_json(&bad.to_string()).is_err());
}
