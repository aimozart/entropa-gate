//! `entropa-check` (TH1): the sealed-run discipline for a user's own guard rules. Schema first: a stage record (not published).

pub mod anchor;
pub mod cli;
pub mod forecast;
pub mod prereg;
pub mod report;
pub mod sealed;
pub mod set;
pub mod stats;
pub mod target;
pub mod wrap;

/// A refusal or failure with a short, input-free message (never echoes case, target or key content).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

impl Refusal {
    /// A refusal with a short message (callers never put file or target content in it).
    pub fn new(msg: &str) -> Refusal {
        Refusal(msg.to_string())
    }
}

/// An id or class name: 1 to 64 characters from `A-Za-z0-9_.-`.
pub fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Parse JSON strictly: valid, no duplicate key anywhere.
pub(crate) fn strict(bytes: &[u8]) -> Result<serde_json::Value, Refusal> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| Refusal::new("the file is not valid UTF-8"))?;
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|_| Refusal::new("the file is not valid JSON"))?;
    if entropa_witness::strict_json::has_duplicate_keys(text) {
        return Err(Refusal::new("the file has a duplicate key"));
    }
    Ok(v)
}

/// sha256 of bytes, lowercase hex.
pub fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Refusal {}
