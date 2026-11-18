//! The private customer dashboard: passwordless email-code login, account
//! status, self-serve API-key regeneration, and a customer-scoped contact
//! form. Mirrors `admin/`'s module shape -- this is the customer-facing
//! sibling of that panel.
//!
//! Private-only, not mirrored to `entropa-public`.

pub mod auth;
mod handlers;
mod store;

/// Re-exported so `transparency_proto` (a sibling module, not a descendant of
/// `dashboard`) can gate its own export/cancel-and-wipe routes behind the exact
/// same customer-session check, and read which partner is authenticated.
pub(crate) use handlers::{require_customer_session, CustomerSlug};

use axum::routing::{get, post};
use axum::Router;

/// Generic over the app's state type, same reasoning as `admin::router()`
/// and `contact::router()` -- none of these handlers extract shared state.
/// CORS is scoped to just these routes (same posture as `contact::router()`)
/// since the dashboard page is a separate, Firebase-hosted origin calling
/// this API cross-origin. No cookies are used, so a wildcard origin is safe
/// here (credentialed requests would need a specific origin instead).
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use tower_http::cors::{Any, CorsLayer};

    let public = Router::new()
        .route(
            "/api/dashboard/login/request",
            post(handlers::login_request),
        )
        .route("/api/dashboard/login/verify", post(handlers::login_verify));

    let protected = Router::new()
        .route("/api/dashboard/me", get(handlers::me))
        .route(
            "/api/dashboard/regenerate-key",
            post(handlers::regenerate_key),
        )
        .route("/api/dashboard/contact", post(handlers::contact))
        .route_layer(axum::middleware::from_fn(
            handlers::require_customer_session,
        ));

    public.merge(protected).layer(
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers(Any),
    )
}
