//! Startup configuration from environment variables only. No secret is ever read or held.

use crate::args::PUBKEY_HEX_MAX;

/// Most trusted keys accepted.
pub const MAX_TRUSTED_KEYS: usize = 8;

/// Startup configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Trusted ML-DSA-65 public keys (lowercase hex, 3904 characters each, at most 8).
    pub trusted_pubkeys: Vec<String>,
    /// Path of the exported log file, if any.
    pub log_file: Option<String>,
}

impl Config {
    /// Read `ENTROPA_TRUSTED_PUBKEYS` (comma separated) and `ENTROPA_LOG_FILE`.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut trusted_pubkeys = Vec::new();
        if let Some(list) = get("ENTROPA_TRUSTED_PUBKEYS") {
            for k in list.split(',').map(str::trim).filter(|k| !k.is_empty()) {
                let ok = k.len() == PUBKEY_HEX_MAX
                    && k.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                if !ok {
                    return Err(
                        "ENTROPA_TRUSTED_PUBKEYS: each key must be 3904 lowercase hex characters"
                            .into(),
                    );
                }
                trusted_pubkeys.push(k.to_string());
            }
        }
        if trusted_pubkeys.len() > MAX_TRUSTED_KEYS {
            return Err(format!(
                "ENTROPA_TRUSTED_PUBKEYS: at most {MAX_TRUSTED_KEYS} keys"
            ));
        }
        let log_file = get("ENTROPA_LOG_FILE")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        Ok(Self {
            trusted_pubkeys,
            log_file,
        })
    }
}
