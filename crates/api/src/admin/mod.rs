//! Internal admin panel — a real, persistent customer/partner registry backed by a
//! new Firestore `partners/{slug}` collection, replacing `PARTNER_KEYS.md`'s
//! fully-manual "hand-edit an env var and redeploy" process.
//!
//! **Fail-closed auth**, the deliberate opposite of `/api/tx`'s fail-open default:
//! if `ENTROPA_ADMIN_SECRET` isn't set, every route here 404s unconditionally. This
//! is the one place in the codebase where "fails soft with zero config" would be
//! actively dangerous — this panel exposes real customer data and API key hashes.
//!
//! **Private-only** — never mirrored to `entropa-public`, same standing exception as
//! `outreach.rs` (see `ARCHITECTURE.md` § Repo split).
//!
//! **Deliberately doesn't yet control live `/api/tx` auth.** `AppState.api_keys`
//! still reads `ENTROPA_API_KEYS` at startup exactly as before — this panel is the
//! first step (a real persistent partner registry to manage and pre-generate keys
//! in), not a live auth cutover. Wiring the two together is a separate, explicitly
//! deferred follow-up, so the riskiest change (swapping the live auth source)
//! doesn't happen at the same time as building a brand-new internal tool.

mod auth;
pub(crate) mod crypto;
mod explorer;
mod handlers;
pub(crate) mod model;
pub(crate) mod store;
mod ui;

use axum::routing::get;
use axum::Router;

use auth::require_admin_auth;
use explorer::internal_explorer_page;
use handlers::api_update_partner;
use handlers::{
    api_create_partner, api_get_partner, api_list_partners, api_login, api_regenerate_key,
    api_search_gmail,
};

/// Re-exported so `transparency_proto` (a sibling module, not a descendant of
/// `admin`) can gate its own tree-deletion/cancel-and-wipe routes behind the
/// exact same fail-closed admin session check -- one auth boundary, not two.
pub(crate) use auth::require_admin_auth as admin_auth_middleware;
use ui::{admin_ui, admin_ui_css, admin_ui_js};

/// Generic over the app's state type — none of these handlers extract shared state
/// (they talk to Firestore directly via `admin::store`), so this merges into whichever
/// binary actually fronts the public internet, same pattern as `contact::router()`.
/// Historically only `main.rs`'s `AppState`-typed router carried this — but `main.rs`
/// hasn't been deployed anywhere since the N=3-quorum decommission, which meant the
/// admin panel (and the key-regeneration recovery path) had no live home at all.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let public = Router::new()
        .route("/admin", get(admin_ui))
        .route("/admin/login", get(admin_ui))
        .route("/admin/new", get(admin_ui))
        .route("/admin/{slug}", get(admin_ui))
        .route("/admin/assets/admin.js", get(admin_ui_js))
        .route("/admin/assets/admin.css", get(admin_ui_css))
        .route("/api/admin/login", axum::routing::post(api_login));
    public.merge(protected_api_router())
}

fn protected_api_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/api/admin/partners",
            get(api_list_partners).post(api_create_partner),
        )
        .route(
            "/api/admin/partners/{slug}",
            get(api_get_partner).post(api_update_partner),
        )
        .route(
            "/api/admin/partners/{slug}/regenerate-key",
            axum::routing::post(api_regenerate_key),
        )
        // Cancel-and-wipe now lives in transparency_proto.rs (needs ProtoState to
        // delete the partner's private tree) -- see admin_cancel_and_wipe there,
        // registered directly on that router but gated by this same auth check
        // via admin_auth_middleware.
        // Real, admin-only Gmail inbox search (aimozart@entropa.space), via the
        // same gmail.rs service-account path everything else emails through.
        // Empty results (not an error) until the gmail.readonly scope is granted
        // in the Workspace admin console alongside the existing gmail.send scope.
        .route("/api/admin/gmail/search", get(api_search_gmail))
        // The internal live explorer -- gated behind the same admin session as
        // everything else here, not a public product surface. Requires having
        // already logged into /admin once in this browser (sets the same cookie
        // `require_admin_auth` checks below).
        .route("/internal-explorer", get(internal_explorer_page))
        .route_layer(axum::middleware::from_fn(require_admin_auth))
}
