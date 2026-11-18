//! Integration tests for the standalone transparency-log prototype — see
//! `a stage record (not published)`. Deliberately exercises the real HTTP
//! surface (`entropa_api::transparency_proto::router`), not just the pure core logic
//! already covered by `entropa-core`'s own unit tests — this is the "wire it up and
//! test it end to end" step.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use entropa_api::transparency_proto::{router, ProtoState};
use entropa_core::transparency_log::{verify_receipt, Receipt};
use tower::ServiceExt;

const PARTNER: &str = "acme";

async fn submit(state: &ProtoState, payload: &str) -> usize {
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tx")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"partner":"{PARTNER}","payload":"{payload}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    value["index"].as_u64().unwrap() as usize
}

async fn fetch_receipt(state: &ProtoState, index: usize) -> (StatusCode, Option<Receipt>, String) {
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/api/receipt/{PARTNER}/{index}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let receipt = serde_json::from_str::<Receipt>(&text).ok();
    (status, receipt, text)
}

#[tokio::test]
async fn submit_then_fetch_receipt_round_trips_and_verifies_end_to_end() {
    let state = ProtoState::new();
    let index = submit(&state, "real-customer-hash-abc123").await;
    let (status, receipt, _) = fetch_receipt(&state, index).await;
    assert_eq!(status, StatusCode::OK);
    let receipt = receipt.expect("valid receipt JSON");
    let pubkey = state.signer_pubkey_hex();
    assert!(
        verify_receipt(&receipt, &pubkey),
        "a real receipt for a real submission must verify"
    );
}

#[tokio::test]
async fn multiple_submissions_each_get_their_own_verifiable_receipt() {
    let state = ProtoState::new();
    let mut indices = Vec::new();
    for payload in ["alpha", "beta", "gamma"] {
        indices.push(submit(&state, payload).await);
    }
    assert_eq!(indices, vec![0, 1, 2]);

    let pubkey = state.signer_pubkey_hex();
    for i in indices {
        let (status, receipt, _) = fetch_receipt(&state, i).await;
        assert_eq!(status, StatusCode::OK);
        assert!(verify_receipt(&receipt.unwrap(), &pubkey));
    }
}

#[tokio::test]
async fn receipt_for_an_index_beyond_the_log_is_404() {
    let state = ProtoState::new();
    submit(&state, "only-one").await;
    let (status, _, _) = fetch_receipt(&state, 99).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn receipt_for_an_unknown_partner_is_404_not_another_customers_data() {
    let state = ProtoState::new();
    submit(&state, "acme-only-record").await;
    let resp = router(state)
        .oneshot(
            Request::builder()
                .uri("/api/receipt/globex/0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_tampered_receipt_over_the_real_wire_format_fails_verification() {
    // Proves the API's own JSON shape is genuinely tamper-evident, not just the
    // in-process Rust structs -- mutate the actual JSON wire bytes a client would
    // receive (record is hex-encoded on the wire, so tamper the hex, not the
    // pre-encoding string, which never appears literally in the JSON).
    let state = ProtoState::new();
    let index = submit(&state, "genuine-payload").await;
    let (_, _, raw_json) = fetch_receipt(&state, index).await;
    let real_hex = hex::encode(b"genuine-payload");
    let forged_hex = hex::encode(b"forged-payload-x");
    assert!(
        raw_json.contains(&real_hex),
        "sanity check: the real record's hex must actually appear in the wire JSON"
    );
    let tampered_json = raw_json.replace(&real_hex, &forged_hex);
    let tampered: Receipt =
        serde_json::from_str(&tampered_json).expect("still valid JSON shape, just wrong content");
    let pubkey = state.signer_pubkey_hex();
    assert!(!verify_receipt(&tampered, &pubkey));
}

#[tokio::test]
async fn submitting_malformed_json_is_a_client_error_not_a_crash() {
    let state = ProtoState::new();
    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tx")
                .header("content-type", "application/json")
                .body(Body::from("not json at all"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn submitting_without_a_partner_is_a_client_error() {
    let state = ProtoState::new();
    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tx")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"payload":"no-partner-here"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn a_submitted_label_is_disclosed_in_chain_but_never_changes_the_payload() {
    // Real production feature, 2026-08-26: an optional, customer-disclosed
    // label rides alongside the opaque payload hash so a customer's own
    // explorer is actually readable, without Entropa ever seeing their real
    // sensitive data (which stays as just the hash).
    let state = ProtoState::new();
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tx")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"partner":"acme","payload":"abc123hash","label":"loan-underwriting:approved"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, body) = get_json(&state, "/api/chain/acme").await;
    let records = body.as_array().unwrap();
    assert_eq!(records[0]["payload"], "abc123hash");
    assert_eq!(records[0]["label"], "loan-underwriting:approved");
}

async fn get_json(state: &ProtoState, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = router(state.clone())
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn health_reports_honest_status_no_fake_consensus_fields() {
    let state = ProtoState::new();
    submit(&state, "one").await;
    submit(&state, "two").await;
    let (status, body) = get_json(&state, "/api/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["height"], 2);
    assert_eq!(body["customers"], 1);
    assert_eq!(
        body["architecture"],
        "single-writer Merkle transparency log — one private tree per customer"
    );
    // Must never claim a consensus/beacon mechanism that no longer exists.
    assert!(body.get("consensus").is_none());
    assert!(body.get("beacon").is_none());
}

#[tokio::test]
async fn health_aggregates_across_multiple_private_trees_without_mixing_their_content() {
    let state = ProtoState::new();
    submit(&state, "acme-one").await;
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tx")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"partner":"globex","payload":"globex-one"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, body) = get_json(&state, "/api/health").await;
    assert_eq!(body["height"], 2, "aggregate across both private trees");
    assert_eq!(body["customers"], 2);
}

#[tokio::test]
async fn chain_returns_records_oldest_first_with_real_payloads() {
    let state = ProtoState::new();
    submit(&state, "first").await;
    submit(&state, "second").await;
    let (status, body) = get_json(&state, &format!("/api/chain/{PARTNER}")).await;
    assert_eq!(status, StatusCode::OK);
    let records = body.as_array().expect("array of records");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["index"], 0);
    assert_eq!(records[0]["payload"], "first");
    assert_eq!(records[1]["index"], 1);
    assert_eq!(records[1]["payload"], "second");
    assert!(!records[0]["hash"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn chain_respects_the_limit_query_param() {
    let state = ProtoState::new();
    for p in ["a", "b", "c", "d", "e"] {
        submit(&state, p).await;
    }
    let (_, body) = get_json(&state, &format!("/api/chain/{PARTNER}?limit=2")).await;
    let records = body.as_array().unwrap();
    assert_eq!(records.len(), 2);
    // Most recent 2, still oldest-first within that window.
    assert_eq!(records[0]["payload"], "d");
    assert_eq!(records[1]["payload"], "e");
}

#[tokio::test]
async fn chain_for_an_unknown_partner_is_an_empty_array_not_another_customers_data() {
    let state = ProtoState::new();
    submit(&state, "acme-only").await;
    let (status, body) = get_json(&state, "/api/chain/globex").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0);
}

/// The real true count, not the (possibly page-capped) number of records in the
/// body -- a customer with more history than `?limit=` would otherwise see the
/// page size itself displayed as their total attestation count, which is wrong.
#[tokio::test]
async fn chain_reports_true_total_via_header_even_when_page_is_capped() {
    let state = ProtoState::new();
    for p in ["a", "b", "c", "d", "e"] {
        submit(&state, p).await;
    }
    let resp = router(state)
        .oneshot(
            Request::builder()
                .uri(format!("/api/chain/{PARTNER}?limit=2"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let total = resp
        .headers()
        .get("x-chain-total")
        .expect("x-chain-total header present")
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert_eq!(total, 5);
}

#[tokio::test]
async fn record_page_renders_and_confirms_independent_verification() {
    let state = ProtoState::new();
    submit(&state, "a-real-record").await;
    let resp = router(state)
        .oneshot(
            Request::builder()
                .uri(format!("/block/{PARTNER}/0"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("a-real-record"));
    assert!(
        html.contains("✅ yes"),
        "a genuine record must show as verified"
    );
}

#[tokio::test]
async fn record_page_missing_index_is_404() {
    let state = ProtoState::new();
    submit(&state, "only-one").await;
    let resp = router(state)
        .oneshot(
            Request::builder()
                .uri(format!("/block/{PARTNER}/99"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
