//! HTTP handlers and router assembly for the transparency-log prototype.

use axum::{
    extract::{Path, Query, State},
    http::{Method, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};

use entropa_core::transparency_log::{decode_record_or_marker, encode_record, verify_receipt};

use crate::html::{esc, BLOCK_PAGE_HEAD};

use super::state::ProtoState;

#[derive(Deserialize)]
struct SubmitRequest {
    partner: String,
    payload: String,
    #[serde(default)]
    label: Option<String>,
}

async fn submit_tx(
    State(state): State<ProtoState>,
    body: Result<Json<SubmitRequest>, axum::extract::rejection::JsonRejection>,
) -> axum::response::Response {
    let Json(req) = match body {
        Ok(json) => json,
        Err(rejection) => return (StatusCode::BAD_REQUEST, rejection.body_text()).into_response(),
    };
    if req.partner.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "partner is required").into_response();
    }

    let record = match encode_record(&req.payload, req.label.as_deref()) {
        Ok(record) => record,
        Err(e) => return (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response(),
    };
    match state.ingest(&req.partner, &record).await {
        Ok(index) => Json(serde_json::json!({ "index": index })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

async fn get_receipt(
    State(state): State<ProtoState>,
    Path((partner, index)): Path<(String, usize)>,
) -> axum::response::Response {
    let partners = state.partners.lock().unwrap();
    let Some(entry) = partners.get(&partner) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(checkpoint) = &entry.latest_checkpoint else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match entry.log.receipt(index, checkpoint) {
        Some(receipt) => Json(receipt).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Honest status for the new architecture — no `consensus`/`beacon` fields pretending
/// multi-party agreement exists, since it doesn't anymore. `height` is the aggregate
/// record count across every customer's private tree (a coarse service-level signal
/// only, never scoped data); `customers` is how many private trees currently exist.
async fn health(State(state): State<ProtoState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "height": state.total_len(),
        "customers": state.partner_count(),
        "architecture": "single-writer Merkle transparency log — one private tree per customer",
        "signature": "ML-DSA (NIST FIPS-204)",
        "network": "Entropa",
        "tagline": "Entropa is boring. All we do is keep your AI agents auditable. For pennies. ($0.01/attestation)",
    }))
}

#[derive(Deserialize)]
struct ChainQuery {
    limit: Option<usize>,
}

/// A page of one partner's own records, oldest-first (matching the old `/api/chain`'s
/// convention that callers reverse for newest-first display). `payload` is the
/// original submitted string, decoded back from the raw record bytes (always valid
/// UTF-8, since it came from a JSON string field).
async fn get_chain(
    State(state): State<ProtoState>,
    Path(partner): Path<String>,
    Query(q): Query<ChainQuery>,
) -> axum::response::Response {
    let limit = q.limit.unwrap_or(50).min(500);
    let partners = state.partners.lock().unwrap();
    let Some(entry) = partners.get(&partner) else {
        return with_chain_total(0, serde_json::json!([]));
    };
    let Some(checkpoint) = entry.latest_checkpoint.clone() else {
        return with_chain_total(0, serde_json::json!([]));
    };
    // Window against the checkpoint's own size, not the raw (possibly
    // further-ahead) in-memory log length -- under concurrent writers the log can
    // grow past the latest checkpoint between an append and its checkpoint update.
    // Reads always resolve against the last *checkpointed* state, which is always
    // fully provable, rather than racing the raw append count and coming up empty.
    let start = checkpoint.size.saturating_sub(limit);
    // Batched, not a per-index `receipt()` loop -- see `receipts_for`'s doc comment
    // for the real 2026-08-27 O(n^2) incident this replaced (this endpoint is
    // polled by the live explorer every 15s, so it hit the same shape of bug).
    let indices: Vec<usize> = (start..checkpoint.size).collect();
    let records: Vec<serde_json::Value> = entry
        .log
        .receipts_for(&indices, &checkpoint)
        .into_iter()
        .zip(indices)
        .filter_map(|(receipt, i)| {
            let receipt = receipt?;
            let (payload, label) = decode_record_or_marker(&receipt.record);
            Some(serde_json::json!({
                "index": receipt.index,
                "hash": hex::encode(entropa_core::merkle::leaf_hash(&receipt.record)),
                "payload": payload,
                "label": label,
                // Each record's own real submission moment -- not the shared
                // checkpoint time. This is the actual product claim.
                "timestamp": entry.submitted_at.get(i).copied(),
            }))
        })
        .collect();
    with_chain_total(checkpoint.size, serde_json::json!(records))
}

/// Attaches the log's true total size as a response header, alongside the
/// (possibly `?limit=`-capped) page of records in the body -- otherwise a caller
/// has no way to distinguish "this customer has exactly N attestations" from
/// "this customer has at least this many, we only sent you a page."
fn with_chain_total(total: usize, records: serde_json::Value) -> axum::response::Response {
    let mut resp = Json(records).into_response();
    resp.headers_mut().insert(
        "x-chain-total",
        axum::http::HeaderValue::from_str(&total.to_string()).unwrap(),
    );
    resp
}

/// Wipes a partner's account entirely (there is no billing any more): their
/// private tree (in memory and in Firestore) and their `PartnerRecord` (email,
/// name, key hash, notes -- their real PII). The owner's explicit call, 2026-08-26:
/// "we wipe it all after cancell." Safe by construction -- see
/// `ProtoState::delete_partner_tree`'s own doc comment -- since this partner's
/// tree was never shared with any other partner's, nobody else's receipts are
/// ever affected. If they sign up again later, it is genuinely a brand new
/// account, with zero trace of the old one.
async fn cancel_and_wipe(state: &ProtoState, slug: &str) -> Result<(), (StatusCode, String)> {
    if crate::admin::store::get_partner(slug).await.is_none() {
        return Err((StatusCode::NOT_FOUND, "not found".to_string()));
    }
    if !state.delete_partner_tree(slug).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "the attestation tree could not be fully wiped -- account record left in place \
             so this can be retried"
                .to_string(),
        ));
    }
    if !crate::admin::store::delete_partner(slug).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "tree wiped, but the account record itself could not be deleted -- check the \
             partner record"
                .to_string(),
        ));
    }
    Ok(())
}

/// `POST /api/admin/partners/{slug}/cancel` -- admin-initiated cancel-and-wipe,
/// gated by the same fail-closed admin session as the rest of the panel.
async fn admin_cancel_and_wipe(
    State(state): State<ProtoState>,
    Path(slug): Path<String>,
) -> axum::response::Response {
    match cancel_and_wipe(&state, &slug).await {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "note": "Account and attestation tree wiped.",
        }))
        .into_response(),
        Err((status, error)) => {
            (status, Json(serde_json::json!({ "error": error }))).into_response()
        }
    }
}

/// `POST /api/dashboard/cancel` -- genuine self-serve cancellation, gated by the
/// customer's own passwordless session (never another customer's).
async fn customer_cancel_and_wipe(
    State(state): State<ProtoState>,
    axum::extract::Extension(crate::dashboard::CustomerSlug(slug)): axum::extract::Extension<
        crate::dashboard::CustomerSlug,
    >,
) -> axum::response::Response {
    match cancel_and_wipe(&state, &slug).await {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "note": "Your account and attestation history have been permanently deleted. \
                     Signing up again starts a brand new account.",
        }))
        .into_response(),
        Err((status, error)) => {
            (status, Json(serde_json::json!({ "error": error }))).into_response()
        }
    }
}

/// A single record's own page — server-rendered, no client JS. Shows the record,
/// recomputes and displays whether it verifies against the current checkpoint (the
/// same check a customer's own `verify_receipt()` call would make), and prev/next
/// navigation matching the old block-detail page's UX. Scoped to one partner's own
/// tree -- an index only ever means something relative to that partner's log.
async fn record_page(
    State(state): State<ProtoState>,
    Path((partner, index)): Path<(String, usize)>,
) -> axum::response::Response {
    let partners = state.partners.lock().unwrap();
    let Some(entry) = partners.get(&partner) else {
        return not_found(index);
    };
    let Some(checkpoint) = entry.latest_checkpoint.clone() else {
        return not_found(index);
    };
    let Some(receipt) = entry.log.receipt(index, &checkpoint) else {
        return not_found(index);
    };
    let signer_pubkey = state.signer.pubkey_hex();
    let height = entry.log.len();
    drop(partners);

    let verified = verify_receipt(&receipt, &signer_pubkey);
    let (payload, label) = decode_record_or_marker(&receipt.record);
    let leaf_hash = hex::encode(entropa_core::merkle::leaf_hash(&receipt.record));
    let prev = index.checked_sub(1);
    let next = index + 1;
    let has_next = next < height;
    let nav = format!(
        "{}<span class=\"sep\">·</span>{}",
        prev.map(|p| format!("<a href=\"/block/{partner}/{p}\">← record {p}</a>"))
            .unwrap_or_else(|| "<span class=\"muted\">← first</span>".to_string()),
        if has_next {
            format!("<a href=\"/block/{partner}/{next}\">record {next} →</a>")
        } else {
            "<span class=\"muted\">latest →</span>".to_string()
        }
    );

    Html(format!(
        "{BLOCK_PAGE_HEAD}<body><div class=\"wrap\">\
        <a class=\"back\" href=\"#\" onclick=\"window.close();return false;\">← Close this tab</a>\
        <h1>Record {index}</h1>\
        <table class=\"fields\">\
        <tr><th>Payload</th><td>{payload}</td></tr>\
        <tr><th>Label</th><td>{label}</td></tr>\
        <tr><th>Leaf hash</th><td class=\"mono\">{leaf_hash}</td></tr>\
        <tr><th>Checkpoint root</th><td class=\"mono\">{root}</td></tr>\
        <tr><th>Checkpoint size</th><td>{size}</td></tr>\
        <tr><th>Checkpoint signature</th><td class=\"mono\">{sig}</td></tr>\
        <tr><th>Independently verified</th><td>{verified}</td></tr>\
        </table>\
        <div class=\"nav\">{nav}</div>\
        </div></body></html>",
        payload = esc(&payload),
        label = esc(label.as_deref().unwrap_or("—")),
        leaf_hash = leaf_hash,
        root = hex::encode(receipt.checkpoint.root),
        size = receipt.checkpoint.size,
        sig = short(&receipt.checkpoint.signature, 32),
        verified = if verified { "✅ yes" } else { "❌ no" },
    ))
    .into_response()
}

fn short(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

fn not_found(index: usize) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Html(format!(
            "{BLOCK_PAGE_HEAD}<body><div class=\"wrap\"><a class=\"back\" \
             href=\"#\" onclick=\"window.close();return false;\">← Close this tab</a>\
             <h1>Record {index} not found</h1></div></body></html>"
        )),
    )
        .into_response()
}

/// Build the router — genuinely new endpoints for the new architecture, not a shim
/// preserving old `proposer_id`/`beacon` fields that don't mean anything here.
pub fn router(state: ProtoState) -> Router {
    let public_read = Router::new()
        .route("/api/tx", post(submit_tx))
        .route("/api/receipt/{partner}/{index}", get(get_receipt))
        .route("/api/health", get(health))
        .route("/api/chain/{partner}", get(get_chain))
        .route("/block/{partner}/{index}", get(record_page))
        // Pub/Sub calls this directly (server-to-server, not a browser) --
        // see `push.rs`'s module doc for why this replaces the old internal
        // pull loop and what actually makes it safe to scale horizontally.
        .route("/internal/pubsub-push", post(super::push::pubsub_push))
        // The website (a separate origin, Firebase-hosted) fetches these read
        // endpoints cross-origin from the browser. /api/tx (state-changing) isn't
        // opened up for browser JS -- server-to-server/curl only, same posture the
        // old validators' CORS layer used.
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET])
                // Custom response headers aren't exposed to browser JS by default
                // under CORS -- `x-chain-total` (get_chain's true-count header)
                // needs this explicitly or `fetch()` silently can't read it.
                .expose_headers(Any),
        );

    // Admin-initiated cancel-and-wipe -- needs ProtoState (to delete the partner's
    // private tree), so it lives here rather than in admin/handlers.rs, but stays
    // gated by that module's own fail-closed session check.
    let admin_wipe = Router::new()
        .route(
            "/api/admin/partners/{slug}/cancel",
            post(admin_cancel_and_wipe),
        )
        .route_layer(axum::middleware::from_fn(
            crate::admin::admin_auth_middleware,
        ));

    // Self-serve export + cancel-and-wipe -- same reasoning, needs ProtoState,
    // gated by the customer's own passwordless session (never another customer's).
    let customer_export_cancel = Router::new()
        .route("/api/dashboard/export", get(super::export::full_export))
        .route("/api/dashboard/cancel", post(customer_cancel_and_wipe))
        .route_layer(axum::middleware::from_fn(
            crate::dashboard::require_customer_session,
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any),
        );

    public_read
        .merge(admin_wipe)
        .merge(customer_export_cancel)
        .with_state(state)
        // The internal partner-management admin panel and its key-regeneration
        // recovery path (fail-closed, 404s entirely unless ENTROPA_ADMIN_SECRET is
        // set) -- merged here since this is the actually-deployed service; it was
        // previously only wired into main.rs, which nothing serves anymore.
        .merge(crate::admin::router())
        // The private customer dashboard: passwordless email-code login and
        // authenticated self-service (account status, key regeneration, contact).
        .merge(crate::dashboard::router())
        // The public contact form (entropa.space/contact) -- real server-side send
        // via the same gmail.rs domain-wide-delegation path, not a client-side
        // mailto: link. No auth: prospects haven't signed up yet.
        .merge(crate::contact::router())
}
