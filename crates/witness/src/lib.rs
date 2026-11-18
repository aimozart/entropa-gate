//! # entropa-witness
//!
//! The pure core of a checkpoint witness, specified in `docs/ARCHITECTURE-WITNESS.md`: it checks a
//! log's signed checkpoint, checks that it extends the last checkpoint the witness accepted, signs a
//! statement, stores the new state with compare-and-swap, and only then returns the statement. No
//! cloud types and no I/O live here: state comes from a [`StateStore`], time from the caller.

use entropa_core::transparency_log::Checkpoint;

mod decode;
mod statement;
pub mod strict_json;
mod witness;

pub use decode::{decode_request, decode_statement};
pub use statement::{log_id_for, statement_canonical_bytes, statement_digest, verify_statement};
pub use witness::Witness;

/// The marker the S5b stubs answered with. Kept so the S5b test helpers still compile; the
/// finished crate never produces it.
pub const NOT_IMPLEMENTED: &str = "not yet implemented";
/// Largest request body the decoder reads, in bytes (64 KiB).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Longest consistency proof accepted, in hashes.
pub const MAX_PROOF_LEN: usize = 64;
/// The statement `type` field.
pub const STATEMENT_TYPE: &str = "witness.cosign";
/// Previous root reported in the statement for the very first checkpoint of a log.
pub const NO_PREVIOUS_ROOT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Why a request was refused or a statement could not be built. Nothing here is ever signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    /// Never produced by the finished crate (kept for the S5b test helpers).
    NotImplemented,
    /// Malformed JSON, wrong shape, unknown field, bad hex or number.
    Invalid(String),
    /// A size limit was exceeded.
    Limit(String),
    /// The `log_id` is not configured.
    UnknownLog,
    /// The checkpoint signature does not verify under the configured log key.
    BadSignature,
    /// No stored state for the log and `allow_first` is off.
    FirstNotAllowed,
    /// The checkpoint is smaller than the stored one.
    Rollback,
    /// Same size as the stored checkpoint but a different root (recorded as evidence).
    Equivocation,
    /// The consistency proof does not connect the stored checkpoint to the new one.
    BadConsistency,
    /// Another writer advanced the state first; nothing was signed, retry.
    StoreConflict,
    /// The state store failed.
    Store(String),
    /// The signer failed.
    Sign(String),
}

/// A log the witness is configured to watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// Lowercase hex BLAKE3 of the log's raw public key (see [`log_id_for`]).
    pub log_id: String,
    /// The log's ML-DSA public key, lowercase hex.
    pub pubkey_hex: String,
    /// Accept the very first checkpoint on trust (once, when no state exists).
    pub allow_first: bool,
}

/// The newest checkpoint a witness accepted for one log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State {
    /// Number of records covered.
    pub size: usize,
    /// Merkle root at `size`.
    pub root: [u8; 32],
}

/// Failure of a state store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The compare-and-swap lost: the stored version is not the expected one.
    Conflict,
    /// Any other failure.
    Failed(String),
}

/// Where the witness keeps its state. `get` returns the state and an opaque version tag;
/// `compare_and_swap` succeeds only when the stored version still equals `expected`
/// (`None` means "no state yet").
pub trait StateStore {
    /// The stored state for `log_id` and its version tag.
    fn get(&self, log_id: &str) -> Result<Option<(State, String)>, StoreError>;
    /// Replace the state if the version is still `expected`.
    fn compare_and_swap(
        &self,
        log_id: &str,
        expected: Option<&str>,
        new: &State,
    ) -> Result<(), StoreError>;
    /// Append evidence of an equivocation (both checkpoints as received).
    fn record_equivocation(&self, log_id: &str, evidence: &str) -> Result<(), StoreError>;
}

impl<T: StateStore + ?Sized> StateStore for std::sync::Arc<T> {
    fn get(&self, log_id: &str) -> Result<Option<(State, String)>, StoreError> {
        (**self).get(log_id)
    }
    fn compare_and_swap(
        &self,
        log_id: &str,
        expected: Option<&str>,
        new: &State,
    ) -> Result<(), StoreError> {
        (**self).compare_and_swap(log_id, expected, new)
    }
    fn record_equivocation(&self, log_id: &str, evidence: &str) -> Result<(), StoreError> {
        (**self).record_equivocation(log_id, evidence)
    }
}

/// A decoded cosign request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The log this checkpoint claims to belong to.
    pub log_id: String,
    /// The log's signed checkpoint.
    pub checkpoint: Checkpoint,
    /// Consistency proof from the witness's stored checkpoint to this one (empty for the first
    /// checkpoint, for an unchanged size, and when the stored size is 0).
    pub consistency: Vec<[u8; 32]>,
}

/// The signed fields of a witness statement (everything except the signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementFields {
    /// The log id.
    pub log_id: String,
    /// Size of the checkpoint the witness saw.
    pub size: u64,
    /// Its root, lowercase hex.
    pub root: String,
    /// The log's own checkpoint timestamp.
    pub log_timestamp: u64,
    /// The witness's clock when it signed.
    pub witness_time: u64,
    /// Size of the checkpoint it extends (0 for the first).
    pub previous_size: u64,
    /// Root of that checkpoint, lowercase hex ([`NO_PREVIOUS_ROOT`] for the first).
    pub previous_root: String,
    /// The witness public key, lowercase hex.
    pub witness_pubkey: String,
}

/// A decoded witness statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The signed fields.
    pub fields: StatementFields,
    /// ML-DSA signature over [`statement_digest`] of [`statement_canonical_bytes`], lowercase hex.
    pub sig: String,
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessError::NotImplemented => write!(f, "{NOT_IMPLEMENTED}"),
            WitnessError::Invalid(m) => write!(f, "invalid input: {m}"),
            WitnessError::Limit(m) => write!(f, "limit exceeded: {m}"),
            WitnessError::UnknownLog => write!(f, "unknown log"),
            WitnessError::BadSignature => write!(f, "signature does not verify"),
            WitnessError::FirstNotAllowed => {
                write!(f, "no stored state and the first checkpoint is not allowed")
            }
            WitnessError::Rollback => write!(f, "checkpoint is older than the stored one"),
            WitnessError::Equivocation => write!(f, "same size with a different root"),
            WitnessError::BadConsistency => {
                write!(f, "consistency proof does not connect the checkpoints")
            }
            WitnessError::StoreConflict => write!(f, "another writer advanced the state, retry"),
            WitnessError::Store(m) => write!(f, "state store failed: {m}"),
            WitnessError::Sign(m) => write!(f, "signing failed: {m}"),
        }
    }
}

impl std::error::Error for WitnessError {}
