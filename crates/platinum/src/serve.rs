//! The serverless ingest: the same operations over HTTP, for Cloud Run (one instance, one writer).
//! Access control is the platform's (private service, caller identity); the body is never echoed.

use crate::{
    export_council, export_decisions, export_evidence, log, log_council, log_evidence, node_signer,
    verify, verify_council, verify_evidence,
};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use std::path::PathBuf;
use std::sync::Arc;

const MAX_BODY: usize = 2 * 1024 * 1024;

type Shared = Arc<(PathBuf, tokio::sync::Mutex<()>)>;

async fn decision(State(s): State<Shared>, body: String) -> (StatusCode, String) {
    let _guard = s.1.lock().await;
    let dir = s.0.clone();
    match tokio::task::spawn_blocking(move || log(&dir, &body)).await {
        Ok(Ok(v)) => (StatusCode::OK, v.to_string()),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            format!("{{\"error\":{}}}", serde_json::Value::String(e)),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"error\":\"internal\"}".to_string(),
        ),
    }
}

async fn evidence(State(s): State<Shared>, body: String) -> (StatusCode, String) {
    let _guard = s.1.lock().await;
    let dir = s.0.clone();
    match tokio::task::spawn_blocking(move || log_evidence(&dir, &body)).await {
        Ok(Ok(v)) => (StatusCode::OK, v.to_string()),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            format!("{{\"error\":{}}}", serde_json::Value::String(e)),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"error\":\"internal\"}".to_string(),
        ),
    }
}

async fn verify_evidence_all(State(s): State<Shared>) -> (StatusCode, String) {
    let _guard = s.1.lock().await;
    let dir = s.0.clone();
    match tokio::task::spawn_blocking(move || verify_evidence(&dir)).await {
        Ok(Ok(t)) => (StatusCode::OK, t),
        Ok(Err(e)) => (StatusCode::CONFLICT, e),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal".to_string()),
    }
}

async fn export_ai(State(s): State<Shared>) -> (StatusCode, String) {
    let _guard = s.1.lock().await;
    let dir = s.0.clone();
    match tokio::task::spawn_blocking(move || export_decisions(&dir)).await {
        Ok(Ok(v)) => (StatusCode::OK, v.to_string()),
        Ok(Err(e)) => (StatusCode::CONFLICT, e),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal".to_string()),
    }
}

async fn council(State(s): State<Shared>, body: String) -> (StatusCode, String) {
    let _guard = s.1.lock().await;
    let dir = s.0.clone();
    match tokio::task::spawn_blocking(move || log_council(&dir, &body)).await {
        Ok(Ok(v)) => (StatusCode::OK, v.to_string()),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            format!("{{\"error\":{}}}", serde_json::Value::String(e)),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"error\":\"internal\"}".to_string(),
        ),
    }
}

async fn verify_council_all(State(s): State<Shared>) -> (StatusCode, String) {
    let _guard = s.1.lock().await;
    let dir = s.0.clone();
    match tokio::task::spawn_blocking(move || verify_council(&dir)).await {
        Ok(Ok(v)) => (StatusCode::OK, v),
        Ok(Err(e)) => (StatusCode::CONFLICT, e),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal".to_string()),
    }
}

async fn export_co(State(s): State<Shared>) -> (StatusCode, String) {
    let _guard = s.1.lock().await;
    let dir = s.0.clone();
    match tokio::task::spawn_blocking(move || export_council(&dir)).await {
        Ok(Ok(v)) => (StatusCode::OK, v.to_string()),
        Ok(Err(e)) => (StatusCode::CONFLICT, e),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal".to_string()),
    }
}

async fn export_ev(State(s): State<Shared>) -> (StatusCode, String) {
    let _guard = s.1.lock().await;
    let dir = s.0.clone();
    match tokio::task::spawn_blocking(move || export_evidence(&dir)).await {
        Ok(Ok(v)) => (StatusCode::OK, v.to_string()),
        Ok(Err(e)) => (StatusCode::CONFLICT, e),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal".to_string()),
    }
}

async fn pubkey(State(s): State<Shared>) -> (StatusCode, String) {
    match node_signer(&s.0) {
        Ok(p) => (StatusCode::OK, p.pubkey_hex()),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "no key".to_string()),
    }
}

async fn verify_all(State(s): State<Shared>) -> (StatusCode, String) {
    let _guard = s.1.lock().await;
    let dir = s.0.clone();
    match tokio::task::spawn_blocking(move || verify(&dir)).await {
        Ok(Ok(t)) => (StatusCode::OK, t),
        Ok(Err(e)) => (StatusCode::CONFLICT, e),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal".to_string()),
    }
}

/// Serve until the process is stopped. A stale `.lock` left by a crashed instance is cleared first:
/// the service runs with one instance, so no other writer exists.
pub fn run(dir: PathBuf) -> Result<(), String> {
    let _ = std::fs::remove_file(dir.join("ledger").join(".lock"));
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0".to_string());
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/decision", post(decision))
        .route("/v1/verify", get(verify_all))
        .route("/v1/pubkey", get(pubkey))
        .route("/v1/evidence", post(evidence))
        .route("/v1/evidence/verify", get(verify_evidence_all))
        .route("/v1/export", get(export_ai))
        .route("/v1/evidence/export", get(export_ev))
        .route("/v1/council", post(council))
        .route("/v1/council/verify", get(verify_council_all))
        .route("/v1/council/export", get(export_co))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(Arc::new((dir, tokio::sync::Mutex::new(()))));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "no runtime".to_string())?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind((bind.as_str(), port))
            .await
            .map_err(|_| "cannot bind".to_string())?;
        axum::serve(listener, app)
            .await
            .map_err(|_| "server stopped".to_string())
    })
}
