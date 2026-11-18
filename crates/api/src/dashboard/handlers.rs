//! HTTP handlers for the customer dashboard's login flow and authenticated
//! actions.

use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use super::auth::{generate_login_code, new_session_for, verify_session, LOGIN_CODE_TTL_SECS};
use super::store::{save_login_code, verify_and_consume_login_code};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn session_secret() -> Option<String> {
    std::env::var("ENTROPA_CUSTOMER_SESSION_SECRET").ok()
}

#[derive(Clone)]
pub(crate) struct CustomerSlug(pub String);

#[derive(Deserialize)]
pub(crate) struct LoginRequestBody {
    email: String,
}

/// `POST /api/dashboard/login/request` -- always returns the same response
/// whether or not the email belongs to a real customer, so this endpoint
/// can't be used to enumerate registered customers.
pub(crate) async fn login_request(Json(body): Json<LoginRequestBody>) -> impl IntoResponse {
    let email = body.email.trim().to_string();
    if let Some(partner) = crate::admin::store::find_partner_by_email(&email).await {
        let code = generate_login_code();
        let code_hash = crate::admin::crypto::hash_key(&code);
        if save_login_code(&email, &code_hash, &partner.slug, now_secs()).await {
            crate::gmail::send_email(
                &email,
                "Your Entropa login code",
                &format!(
                    "Your login code is {code}. It expires in {} minutes.",
                    LOGIN_CODE_TTL_SECS / 60
                ),
            )
            .await;
        }
    }
    Json(json!({"ok": true, "message": "If that email has an Entropa account, a code was sent."}))
}

#[derive(Deserialize)]
pub(crate) struct LoginVerifyBody {
    email: String,
    code: String,
}

/// `POST /api/dashboard/login/verify` -- exchanges a correct code for a
/// session token. Fails closed (503) if the session secret isn't configured,
/// same posture as the admin panel's own auth.
pub(crate) async fn login_verify(Json(body): Json<LoginVerifyBody>) -> axum::response::Response {
    let Some(secret) = session_secret() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "dashboard login is not configured yet"})),
        )
            .into_response();
    };
    match verify_and_consume_login_code(&body.email, &body.code, now_secs()).await {
        Some(slug) => {
            let token = new_session_for(&slug, now_secs(), &secret);
            Json(json!({"session_token": token})).into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "that code is wrong or has expired"})),
        )
            .into_response(),
    }
}

/// Gates every `/api/dashboard/{me,regenerate-key,contact}` route behind a
/// valid bearer session token, inserting the authenticated slug into request
/// extensions for handlers to read -- a customer can only ever act on their
/// own account, never one supplied via a path/body parameter.
pub(crate) async fn require_customer_session(
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> axum::response::Response {
    let Some(secret) = session_secret() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "").into_response();
    };
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(slug) = token.and_then(|t| verify_session(t, &secret, now_secs())) else {
        return (StatusCode::UNAUTHORIZED, "").into_response();
    };
    request.extensions_mut().insert(CustomerSlug(slug));
    next.run(request).await
}

pub(crate) async fn me(
    axum::extract::Extension(CustomerSlug(slug)): axum::extract::Extension<CustomerSlug>,
) -> axum::response::Response {
    match crate::admin::store::get_partner(&slug).await {
        Some(p) => Json(json!({
            "slug": p.slug,
            "display_name": p.display_name,
        }))
        .into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

pub(crate) async fn regenerate_key(
    axum::extract::Extension(CustomerSlug(slug)): axum::extract::Extension<CustomerSlug>,
) -> axum::response::Response {
    match crate::admin::store::regenerate_key_for(&slug).await {
        Some((_, raw_key)) => Json(json!({
            "raw_key": raw_key,
            "note": "Shown once — copy it now. The previous key stops working immediately.",
        }))
        .into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

#[derive(Deserialize)]
pub(crate) struct ContactBody {
    message: String,
}

pub(crate) async fn contact(
    axum::extract::Extension(CustomerSlug(slug)): axum::extract::Extension<CustomerSlug>,
    Json(body): Json<ContactBody>,
) -> axum::response::Response {
    let Some(partner) = crate::admin::store::get_partner(&slug).await else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    };
    let sent = crate::gmail::send_email(
        "aimozart@entropa.space",
        &format!(
            "Entropa Dashboard — {slug} — {}",
            body.message.chars().take(40).collect::<String>()
        ),
        &format!(
            "From dashboard customer: {slug} ({})\n\n{}",
            partner.email, body.message
        ),
    )
    .await;
    if sent {
        Json(json!({"ok": true})).into_response()
    } else {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "could not send — email aimozart@entropa.space directly"})),
        )
            .into_response()
    }
}
