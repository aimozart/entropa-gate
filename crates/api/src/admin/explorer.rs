//! The internal live explorer -- full record browsing plus a real date-range filter,
//! backed directly by the already-public `/api/chain` read endpoint (no new GCP
//! resources, no duplicated data path). What's actually private here is the page
//! itself: gated behind the same admin session as the rest of `admin/`, so it never
//! becomes a public product surface, even though the underlying read data it
//! displays was already public before this page existed.

use axum::response::Html;

pub(crate) async fn internal_explorer_page() -> Html<&'static str> {
    Html(include_str!("internal_explorer.html"))
}
