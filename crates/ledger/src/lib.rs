//! # entropa-ledger
//!
//! The core the public explorer depends on (`docs/ARCHITECTURE-EXPLORER.md`): a closed-code,
//! data-minimal event schema; an append-only ledger store with a local-file implementation; a
//! deterministic synthetic scenario generator that drives the real Cedar, approvals and witness
//! crates with per-actor keys; and the export of a static JSON bundle that the front end and the
//! WebAssembly verifier consume, together with a standalone bundle verifier.

mod bundle;
mod council;
mod event;
mod evidence;
#[cfg(feature = "engine")]
mod generator;
mod keys;
mod plain;
mod platinum;
mod raw;
#[cfg(feature = "engine")]
mod scenarios;
mod store;
mod vocab;

pub use bundle::{verify_bundle, BundleReport};
pub use council::{council_fields, CouncilStep};
pub use event::{
    decode_event, encode_event, event_canonical_bytes, event_digest, sign_event, verify_event,
    AgentMeta, Event, EventFields, EvidenceMeta,
};
pub use evidence::{evidence_fields, EvidenceRecord};
#[cfg(feature = "engine")]
pub use generator::{Generator, RunSummary};
pub use keys::Keys;
pub use plain::plain_english;
pub use platinum::{platinum_fields, PlatinumDecision};
pub use raw::{read_raw, read_raw_with, RawLedger, MAX_CHECKPOINT_LINE, MAX_RECORD_LINE};
pub use store::{FileStore, LedgerStore, MemoryStore};
pub use vocab::{
    ControlCode, Decision, Handle, Kind, LabelCode, Provider, ReasonCode, RoleCode, Tenant,
};

/// The marker the S7b stubs answered with. Kept so the S7b test helpers still compile; the
/// finished crate never produces it.
pub const NOT_IMPLEMENTED: &str = "not yet implemented";
/// Largest event payload accepted by the decoder, in bytes.
pub const MAX_EVENT_BYTES: usize = 16 * 1024;
/// Largest bundle the exporter may produce, in bytes (5 MiB).
pub const MAX_BUNDLE_BYTES: usize = 5 * 1024 * 1024;
/// The `type` field of every event this crate writes.
pub const EVENT_TYPE: &str = "explorer.event";

/// Errors from this crate. No message ever echoes an offending input value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// Never produced by the finished crate (kept for the S7b test helpers).
    NotImplemented,
    /// Malformed or out-of-vocabulary input.
    Invalid(String),
    /// A size limit was exceeded.
    Limit(String),
    /// The store's files cannot be used (I/O failure, store already open).
    Io(String),
    /// The store's content is inconsistent with its checkpoints or truncated.
    Corrupt(String),
    /// Signing failed.
    Sign(String),
    /// A signature, receipt, proof or statement did not verify.
    Verify(String),
}
