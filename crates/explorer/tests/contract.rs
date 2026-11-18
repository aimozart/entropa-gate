//! The GET-only read API: shapes, paging, receipts, errors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::transparency_log::{verify_receipt, Receipt};

#[test]
fn c1_health_and_head_report_the_loaded_log() {
    let e = explorer();
    assert_eq!(json(&ask(&e, "/api/healthz"))["status"], "ok");
    let h = json(&ask(&e, "/api/head"));
    let f = fixture();
    assert_eq!(h["checkpoint"], f["head"]);
    assert_eq!(h["size"], f["records"].as_array().unwrap().len());
    assert_eq!(h["synthetic"], true);
}

#[test]
fn c2_records_page_newest_first_and_the_cursor_walks_every_record_once() {
    let e = explorer();
    let total = fixture()["records"].as_array().unwrap().len() as u64;
    let mut seen = vec![];
    let mut target = "/api/records?limit=7".to_string();
    loop {
        let v = json(&ask(&e, &target));
        for it in v["items"].as_array().unwrap() {
            assert!(it.get("record_hex").is_none(), "lists carry summaries only");
            seen.push(it["index"].as_u64().unwrap());
        }
        match v["next_cursor"].as_u64() {
            Some(c) => target = format!("/api/records?limit=7&cursor={c}"),
            None => break,
        }
    }
    let want: Vec<u64> = (0..total).rev().collect();
    assert_eq!(seen, want);
}

#[test]
fn c3_record_detail_receipt_and_proof_verify_with_the_core_verifier() {
    let e = explorer();
    let f = fixture();
    let log_key = f["log"]["pubkey_hex"].as_str().unwrap().to_string();
    for i in [0usize, 7, 24] {
        let d = json(&ask(&e, &format!("/api/records/{i}")));
        assert_eq!(d["record_hex"], f["records"][i]["record_hex"]);
        let r = json(&ask(&e, &format!("/api/receipts/{i}")));
        let receipt = Receipt {
            index: i,
            record: hex::decode(r["record_hex"].as_str().unwrap()).unwrap(),
            proof: serde_json::from_value(r["proof"].clone()).unwrap(),
            checkpoint: serde_json::from_value(r["checkpoint"].clone()).unwrap(),
        };
        assert!(verify_receipt(&receipt, &log_key), "receipt {i}");
    }
}

#[test]
fn c4_a_receipt_asked_for_another_size_or_a_missing_record_is_refused() {
    let e = explorer();
    assert_eq!(
        ask(&e, "/api/receipts/3?size=9").status,
        404,
        "only the head size is served"
    );
    assert_eq!(ask(&e, "/api/receipts/3?size=25").status, 200);
    assert_eq!(ask(&e, "/api/receipts/25").status, 404);
    assert_eq!(ask(&e, "/api/records/25").status, 404);
    assert_eq!(
        ask(&e, "/api/consistency?old=3&new=25").status,
        404,
        "only checkpoint sizes"
    );
    assert_eq!(
        ask(&e, "/api/actors/reviewer").status,
        404,
        "internal names are not handles"
    );
    assert_eq!(ask(&e, "/api/feeds/nobody").status, 404);
}

#[test]
fn c5_only_get_and_options_are_allowed() {
    let e = explorer();
    let clock = FakeClock::at(NOW);
    for m in [
        "POST", "PUT", "DELETE", "PATCH", "HEAD", "TRACE", "CONNECT", "get",
    ] {
        let r = e.handle(&from(m, "/api/head", CLIENT), &clock);
        if r.status == 501 {
            panic!("{NOT_IMPLEMENTED}");
        }
        assert_eq!(r.status, 405, "{m}");
        assert_eq!(
            r.headers.get("allow").map(String::as_str),
            Some("GET, OPTIONS"),
            "{m}"
        );
    }
    let p = e.handle(&from("OPTIONS", "/api/head", "198.51.100.1"), &clock);
    assert_eq!(p.status, 204);
    assert_eq!(p.body, "");
}

#[test]
fn c6_a_request_with_a_body_is_refused_and_unknown_paths_are_404() {
    let e = explorer();
    let clock = FakeClock::at(NOW);
    let mut r = get("/api/head");
    r.body_len = 1;
    let out = e.handle(&r, &clock);
    if out.status == 501 {
        panic!("{NOT_IMPLEMENTED}");
    }
    assert_eq!(out.status, 400);
    for p in [
        "/",
        "/api",
        "/api/",
        "/api/nothing",
        "/api/head/extra",
        "/index.html",
        "/api/records/-1",
        "/api/records/01",
    ] {
        assert_eq!(ask(&e, p).status, 404, "{p}");
    }
}

#[test]
fn c7_actor_pages_use_role_handles_only() {
    let e = explorer();
    let list = json(&ask(&e, "/api/actors"));
    let items = list["items"].as_array().unwrap();
    assert!(items.iter().any(|a| a["handle"] == "human-principal"));
    let page = json(&ask(&e, "/api/actors/human-principal"));
    assert_eq!(page["actor"]["status"], "keyless");
    assert!(page["records"].as_u64().unwrap() >= 1);
}

#[test]
fn c8_witness_statements_filter_by_size() {
    let e = explorer();
    assert_eq!(
        json(&ask(&e, "/api/witnesses"))["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        json(&ask(&e, "/api/witnesses?size=9"))["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        json(&ask(&e, "/api/witnesses?size=4"))["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}
