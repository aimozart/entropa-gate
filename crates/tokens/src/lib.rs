//! # entropa-tokens (AT1 spike)
//!
//! Capability tokens signed with ML-DSA-65 that verify fully offline. Two designs are compared under the same bars: design A (one signed token;
//! narrowing means the issuer signs a new, narrower token) and design C (an append-only chain of signed blocks; the holder narrows offline).
//! Nothing here reads a clock, a file or the network: every verification takes the time and the trust store as inputs, and answers with
//! either the effective claims or one reason from a closed list ([`Deny`]). Wording: tested against the planted attacks in `tests/`, no more.

pub mod canon;
pub mod claims;
mod design_a;
mod design_c;
mod revoke;
pub mod testing;
mod verify;

pub use claims::{check_narrower, Claims, Tier};
pub use design_a::{issue_a, narrow_a, verify_a, MAX_A_BYTES};
pub use design_c::{append_c, issue_c, verify_c, Narrowing, Wallet, MAX_BLOCKS, MAX_C_BYTES};
pub use revoke::{empty_revocations, issue_revocations, Reason, MAX_LIST_BYTES};
pub use verify::{
    digest, key_id_of, Deny, Policy, Trust, Verified, ALG, PUBKEY_HEX_LEN, SIG_HEX_LEN,
};

/// Why a token could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueError {
    /// A claim is outside its closed set or limit (the field is named).
    InvalidClaims(&'static str),
    /// A child would exceed its parent (the field is named).
    Widened(&'static str),
    /// The key is not the one the token commits to, or is not a well-formed ML-DSA-65 key.
    KeyMismatch,
    /// More blocks than allowed.
    TooManyBlocks,
    /// The token bytes could not be read.
    Parse,
    /// The result would be larger than the limit.
    TooLarge,
}
