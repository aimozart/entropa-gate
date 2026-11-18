//! Fail-closed auth for every `/admin/*` route — the deliberate opposite of
//! `/api/tx`'s fail-open default (see `admin/mod.rs`'s module doc for why).

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

pub(crate) const SESSION_COOKIE: &str = "entropa_admin_session";

/// Pure, testable auth check: does `headers` carry a bearer token matching
/// `configured_secret`? If `configured_secret` is `None` (env var unset), this
/// **always returns `false`** — fail-closed, never fail-open, regardless of what's
/// in the request.
///
/// Accepts either an `Authorization: Bearer <secret>` header (API clients, curl,
/// Postman) or a session cookie set by `/admin/login` (a real browser login flow) —
/// both are checked against the exact same configured secret, so there's only one
/// credential to manage, just two ways to present it.
pub(crate) fn check_admin_auth(headers: &HeaderMap, configured_secret: Option<&str>) -> bool {
    let Some(secret) = configured_secret else {
        return false;
    };
    let bearer_ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|token| token == secret);
    if bearer_ok {
        return true;
    }
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|cookie_str| {
            cookie_str.split(';').any(|kv| {
                kv.trim()
                    .strip_prefix(&format!("{SESSION_COOKIE}="))
                    .is_some_and(|v| v == secret)
            })
        })
}

pub(crate) fn unauthorized_404() -> axum::response::Response {
    (StatusCode::NOT_FOUND, "").into_response()
}

/// Axum middleware: gate every `/admin/*` route behind `check_admin_auth`. 404s
/// (not 401/403) on failure — doesn't reveal that an admin panel exists at all to
/// an unauthenticated caller.
pub(crate) async fn require_admin_auth(
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let configured = std::env::var("ENTROPA_ADMIN_SECRET").ok();
    if check_admin_auth(&headers, configured.as_deref()) {
        next.run(request).await
    } else {
        unauthorized_404()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_fails_closed_when_secret_is_unconfigured() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer anything-at-all".parse().unwrap(),
        );
        // Even a request that "looks right" must fail if no secret is configured —
        // this is the one place fail-open would be actively dangerous.
        assert!(!check_admin_auth(&headers, None));
    }

    #[test]
    fn auth_rejects_wrong_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer wrong-token".parse().unwrap(),
        );
        assert!(!check_admin_auth(&headers, Some("correct-secret")));
    }

    #[test]
    fn auth_rejects_missing_header() {
        assert!(!check_admin_auth(&HeaderMap::new(), Some("correct-secret")));
    }

    #[test]
    fn auth_accepts_correct_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer correct-secret".parse().unwrap(),
        );
        assert!(check_admin_auth(&headers, Some("correct-secret")));
    }

    #[test]
    fn auth_accepts_correct_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("{SESSION_COOKIE}=correct-secret; other=ignored")
                .parse()
                .unwrap(),
        );
        assert!(check_admin_auth(&headers, Some("correct-secret")));
    }

    #[test]
    fn auth_rejects_wrong_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("{SESSION_COOKIE}=wrong-value").parse().unwrap(),
        );
        assert!(!check_admin_auth(&headers, Some("correct-secret")));
    }

    #[test]
    fn auth_cookie_also_fails_closed_when_secret_unconfigured() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("{SESSION_COOKIE}=anything").parse().unwrap(),
        );
        assert!(!check_admin_auth(&headers, None));
    }
}
