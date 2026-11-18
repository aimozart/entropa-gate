//! Serves the compiled React admin UI (a single embedded static bundle).

use axum::response::IntoResponse;

/// Serves the compiled React admin UI at any `/admin*` path not otherwise matched
/// by the JSON API — the SPA's own client-side router handles the actual page
/// (login vs. list vs. detail).
pub(crate) async fn admin_ui() -> impl IntoResponse {
    axum::response::Html(ADMIN_UI_HTML)
}

static ADMIN_UI_HTML: &str = include_str!("../../../../admin-ui/dist/index.html");
static ADMIN_UI_JS: &str = include_str!("../../../../admin-ui/dist/assets/admin.js");
static ADMIN_UI_CSS: &str = include_str!("../../../../admin-ui/dist/assets/admin.css");

pub(crate) async fn admin_ui_js() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        ADMIN_UI_JS,
    )
}

pub(crate) async fn admin_ui_css() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css")],
        ADMIN_UI_CSS,
    )
}
