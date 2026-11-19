//! `entropa-gate`: the client-installed app. Slice A (S1 task 2): `init`, `record`, `verify`, `status` and a strict config. The library holds
//! no network code and never returns key bytes (a stage record (not published), invariants I1 to I6). The node functions are built on `entropa-ledger`
//! and `entropa-core` directly, NOT on `entropa-platinum`, which carries `reqwest`, `axum`, `tokio` and a cloud-KMS path a client binary must not hold.

pub mod check;
pub mod cli;
pub mod config;
pub mod explorer;
pub mod keys;
pub mod licence;
#[cfg(feature = "issue")]
pub mod licence_issue;
pub mod node;
pub mod opts;
#[cfg(feature = "plant")]
pub mod plant;

/// A short, input-free error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    /// The request or file is not acceptable (the text names the field, never the value).
    Invalid(String),
    /// A file or directory problem (permissions, missing key, already initialised).
    Io(String),
    /// Verification of a ledger failed.
    Verify(String),
    /// Not built yet (red phase).
    NotImplemented,
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::Invalid(m) => write!(f, "invalid: {m}"),
            GateError::Io(m) => write!(f, "io: {m}"),
            GateError::Verify(m) => write!(f, "verify failed: {m}"),
            GateError::NotImplemented => write!(f, "not yet implemented"),
        }
    }
}
impl std::error::Error for GateError {}

/// Result type of the library.
pub type Res<T> = Result<T, GateError>;
