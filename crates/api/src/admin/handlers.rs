//! HTTP handlers for the partner-management JSON API and admin login.

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use super::auth::{unauthorized_404, SESSION_COOKIE};
use super::crypto::{generate_key, hash_key, slugify};
use super::model::PartnerRecord;
use super::store::{get_partner, list_partners, partner_json, regenerate_key_for, save_partner};

pub(crate) async fn api_list_partners() -> impl IntoResponse {
    let partners = list_partners().await;
    Json(json!({
        "partners": partners.iter().map(partner_json).collect::<Vec<_>>()
    }))
}

pub(crate) async fn api_get_partner(Path(slug): Path<String>) -> axum::response::Response {
    match get_partner(&slug).await {
        Some(p) => Json(partner_json(&p)).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

#[derive(Deserialize)]
pub(crate) struct NewPartnerRequest {
    display_name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    notes: String,
}

pub(crate) async fn api_create_partner(Json(body): Json<NewPartnerRequest>) -> impl IntoResponse {
    let slug = slugify(&body.display_name);
    let raw_key = generate_key();
    let record = PartnerRecord {
        slug: slug.clone(),
        display_name: body.display_name,
        email: body.email,
        api_key_hash: hash_key(&raw_key),
        notes: body.notes,
    };
    save_partner(&record).await;
    Json(json!({
        "partner": partner_json(&record),
        "raw_key": raw_key,
        "note": "Raw key shown once — copy it now, it is not recoverable from this panel again. \
                 To actually gate /api/tx with it, add it to ENTROPA_API_KEYS and redeploy.",
    }))
}

/// `POST /api/admin/partners/{slug}/regenerate-key` — issues a fresh key when a
/// customer reports losing theirs (the one real gap in the never-store-plaintext
/// design: nobody, including us, can recover a lost key, only replace it). The old
/// key's hash is overwritten, so it stops authenticating immediately.
pub(crate) async fn api_regenerate_key(Path(slug): Path<String>) -> axum::response::Response {
    let Some((p, raw_key)) = regenerate_key_for(&slug).await else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    };
    Json(json!({
        "partner": partner_json(&p),
        "raw_key": raw_key,
        "note": "Raw key shown once — copy it now. The previous key stops working immediately.",
    }))
    .into_response()
}

// The admin-only cancel endpoint used to live here, marking a partner
// `Canceled` and leaving their record (and shared-log data) in place forever.
// Superseded 2026-08-26 by a real wipe -- see
// `transparency_proto::admin_cancel_and_wipe`, which needs `ProtoState` (to
// delete the partner's private tree) and so lives where that state is
// concretely available, rather than here.

#[derive(Deserialize)]
pub(crate) struct GmailSearchQuery {
    q: String,
    #[serde(default = "default_max_results")]
    max: u32,
}

fn default_max_results() -> u32 {
    10
}

/// `GET /api/admin/gmail/search?q=...` — searches `aimozart@entropa.space`'s real
/// inbox via the same domain-wide-delegation service account `gmail.rs` sends
/// through, using the `gmail.readonly` scope. Admin-only (same fail-closed auth
/// as every other route in this panel) since this reads real customer/support
/// correspondence. Returns an empty list (not an error) if the readonly scope
/// hasn't been granted yet in the Workspace admin console — `gmail::search_recent`
/// fails soft, same posture as `send_email`.
pub(crate) async fn api_search_gmail(
    axum::extract::Query(query): axum::extract::Query<GmailSearchQuery>,
) -> axum::response::Response {
    let results = crate::gmail::search_recent(&query.q, query.max).await;
    Json(json!({
        "results": results.iter().map(|m| json!({
            "id": m.id,
            "subject": m.subject,
            "from": m.from,
            "date": m.date,
            "snippet": m.snippet,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub(crate) struct UpdatePartnerRequest {
    display_name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    notes: String,
}

pub(crate) async fn api_update_partner(
    Path(slug): Path<String>,
    Json(body): Json<UpdatePartnerRequest>,
) -> axum::response::Response {
    let Some(mut p) = get_partner(&slug).await else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    };
    p.display_name = body.display_name;
    p.email = body.email;
    p.notes = body.notes;
    save_partner(&p).await;
    Json(partner_json(&p)).into_response()
}

#[derive(Deserialize)]
pub(crate) struct LoginRequest {
    secret: String,
}

pub(crate) async fn api_login(Json(body): Json<LoginRequest>) -> axum::response::Response {
    let Ok(configured) = std::env::var("ENTROPA_ADMIN_SECRET") else {
        return unauthorized_404();
    };
    if body.secret.is_empty() || body.secret != configured {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "wrong secret"})),
        )
            .into_response();
    }
    let cookie = format!(
        "{SESSION_COOKIE}={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
        body.secret
    );
    (
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(json!({"ok": true})),
    )
        .into_response()
}
