//! Public contact form — `entropa.space/contact`. Unlike the dashboard's
//! contact form (customer-scoped, session-gated), this one is for prospects
//! who haven't signed up yet, so it takes no auth. Sends through the same
//! `gmail::send_email` domain-wide-delegation path as everything else in
//! this codebase that emails — never a client-side `mailto:` link.

#[cfg(test)]
mod pure_logic_tests {
    use super::*;

    #[test]
    fn a_well_formed_submission_is_valid() {
        assert!(is_valid_contact("Jane Prospect", "jane@example.com", "hi"));
    }

    #[test]
    fn an_empty_name_is_rejected() {
        assert!(!is_valid_contact("", "jane@example.com", "hi"));
    }

    #[test]
    fn an_email_without_an_at_sign_is_rejected() {
        assert!(!is_valid_contact("Jane", "not-an-email", "hi"));
    }

    #[test]
    fn an_empty_message_is_rejected() {
        assert!(!is_valid_contact("Jane", "jane@example.com", ""));
    }

    #[test]
    fn an_oversized_message_is_rejected() {
        let huge = "a".repeat(10_001);
        assert!(!is_valid_contact("Jane", "jane@example.com", &huge));
    }

    #[test]
    fn build_contact_email_carries_the_reason_in_the_subject() {
        let (subject, _) = build_contact_email("Jane", "jane@example.com", "sales", "hi there");
        assert_eq!(subject, "Entropa contact — sales");
    }

    #[test]
    fn build_contact_email_body_carries_sender_identity_and_message() {
        let (_, body) = build_contact_email("Jane", "jane@example.com", "sales", "hi there");
        assert!(body.contains("Jane"));
        assert!(body.contains("jane@example.com"));
        assert!(body.contains("hi there"));
    }

    #[test]
    fn build_contact_email_falls_back_to_a_default_reason_when_blank() {
        let (subject, _) = build_contact_email("Jane", "jane@example.com", "", "hi there");
        assert_eq!(subject, "Entropa contact — general");
    }
}

const MAX_FIELD_LEN: usize = 10_000;

fn is_valid_contact(name: &str, email: &str, message: &str) -> bool {
    !name.trim().is_empty()
        && email.contains('@')
        && !message.trim().is_empty()
        && message.len() <= MAX_FIELD_LEN
        && name.len() <= MAX_FIELD_LEN
}

fn build_contact_email(name: &str, email: &str, reason: &str, message: &str) -> (String, String) {
    let reason = if reason.trim().is_empty() {
        "general"
    } else {
        reason.trim()
    };
    let subject = format!("Entropa contact — {reason}");
    let body = format!("From: {name} <{email}>\nReason: {reason}\n\n{message}");
    (subject, body)
}

#[derive(serde::Deserialize)]
pub struct ContactRequest {
    name: String,
    email: String,
    #[serde(default)]
    reason: String,
    message: String,
}

/// `POST /api/contact` — the public contact form's real send path.
pub async fn submit_contact(
    axum::Json(body): axum::Json<ContactRequest>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serde_json::json;

    if !is_valid_contact(&body.name, &body.email, &body.message) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(
                json!({"error": "name, a valid email, and a non-empty message are required"}),
            ),
        )
            .into_response();
    }

    let (subject, email_body) =
        build_contact_email(&body.name, &body.email, &body.reason, &body.message);
    let sent = crate::gmail::send_email("aimozart@entropa.space", &subject, &email_body).await;

    if sent {
        (StatusCode::OK, axum::Json(json!({"ok": true}))).into_response()
    } else {
        (
            StatusCode::BAD_GATEWAY,
            axum::Json(json!({"error": "could not send — email aimozart@entropa.space directly"})),
        )
            .into_response()
    }
}

/// Generic over the app's state type, same reasoning as `admin::router()`/
/// `dashboard::router()` — this handler extracts no shared state. CORS is
/// scoped to just this route since the public site is a separate,
/// Firebase-hosted origin calling this API cross-origin.
pub fn router<S>() -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use axum::routing::post;
    use tower_http::cors::{Any, CorsLayer};

    axum::Router::new()
        .route("/api/contact", post(submit_contact))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([axum::http::Method::POST])
                .allow_headers(Any),
        )
}
