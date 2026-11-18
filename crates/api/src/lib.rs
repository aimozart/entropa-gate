//! # Entropa API
//!
//! The single-writer Merkle transparency log's backend, split across two real
//! production binaries (`bin/ingest_service.rs`, `bin/transparency_service.rs` —
//! see `ARCHITECTURE.md`). This crate is a library of the modules those binaries
//! (and the customer-facing dashboard/admin panel merged into
//! [`transparency_proto::router`]) are built from — it has no `main.rs` and no
//! top-level `app()` of its own; each binary assembles the router it needs
//! directly from these modules.
//!
//! The public marketing site (landing page, Scryon explorer, `/hire`, `/resume`,
//! `/glossary`) is a separate, statically-hosted service that reads chain data
//! purely as an HTTP client of the transparency service — this crate carries no
//! marketing HTML.

mod admin;
pub mod contact;
pub mod dashboard;
pub mod gmail;
pub mod heartbeat;
mod html;
pub mod ingest;
pub mod partner_directory;
pub mod persistence;
pub mod pubsub;
pub mod pull_subscriber;
pub mod sequencer;
pub mod transparency_persistence;
pub mod transparency_proto;
