//! Standalone end-to-end prototype: single writer + Merkle transparency log, wired
//! into a real axum router — entirely separate from the live production router in
//! `lib.rs`/`main.rs`, which still runs the N=3 quorum system serving real customers.
//! See `a stage record (not published)`. Deliberately not merged into `app()`
//! until a migration decision is actually made, per the project rules.
//!
//! **Each customer gets their own private Merkle tree — never intermingled with
//! another customer's usage, in storage or in the tree math itself.** the owner's
//! explicit call, 2026-08-26: "cant intermingle... ea customer get st he perosnal
//! tree." This is also what makes real account deletion possible: deleting one
//! partner's tree can never invalidate another partner's already-issued receipts,
//! since the trees were never shared to begin with (the problem that made deleting
//! from a single shared log structurally impossible).

mod export;
mod handlers;
mod push;
mod rate_tier;
mod state;

pub use handlers::router;
pub use state::ProtoState;
