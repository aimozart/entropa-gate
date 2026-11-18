//! What every verification shares: the trust store, the verifier's policy (time, audience, skew, TTL cap, revocation age), the closed list of
//! reasons a token is refused, the signed digest and the policy checks. Nothing here reads a clock or a file.

use crate::claims::Claims;
use std::collections::BTreeMap;

/// The only signature algorithm. There is no negotiation and no "none".
pub const ALG: &str = "ML-DSA-65";
/// ML-DSA-65 public key length in hex characters (1,952 bytes).
pub const PUBKEY_HEX_LEN: usize = 1952 * 2;
/// ML-DSA-65 signature length in hex characters (3,309 bytes).
pub const SIG_HEX_LEN: usize = 3309 * 2;

/// Why a token, a block or a revocation list was refused. Closed: nothing else ever leaves the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deny {
    /// Larger than the limit for its kind.
    TooLarge,
    /// Not the accepted shape (syntax, keys, fields, closed sets).
    Malformed,
    /// An object holds a key twice.
    DuplicateKey,
    /// Valid JSON of the right shape, but not byte-for-byte the canonical form.
    NotCanonical,
    /// The algorithm field is not `ML-DSA-65`.
    BadAlgorithm,
    /// The issuer `key_id` is not in the trust store.
    UnknownKey,
    /// A signature does not verify (or a block is not chained to the previous one).
    BadSignature,
    /// `now` is before `not_before` less the allowed skew.
    NotYetValid,
    /// `now >= expiry`.
    Expired,
    /// The token is for another node.
    WrongAudience,
    /// `expiry - not_before` is more than the verifier's TTL cap.
    TtlTooLong,
    /// The token (or its parent or root) is in the revocation list.
    Revoked,
    /// No revocation list was supplied.
    RevocationMissing,
    /// The revocation list is older than the maximum age.
    RevocationStale,
    /// The revocation list is malformed, unsigned, signed by an untrusted key, or dated in the future.
    RevocationInvalid,
    /// A child exceeds its parent on some field.
    Widened,
    /// The parent presented is not the parent named, or was not signed by the same key.
    ParentMismatch,
    /// More blocks than allowed.
    TooManyBlocks,
}

impl Deny {
    /// The reason code written to the trail.
    pub fn as_str(self) -> &'static str {
        match self {
            Deny::TooLarge => "too_large",
            Deny::Malformed => "malformed",
            Deny::DuplicateKey => "duplicate_key",
            Deny::NotCanonical => "not_canonical",
            Deny::BadAlgorithm => "bad_algorithm",
            Deny::UnknownKey => "unknown_key",
            Deny::BadSignature => "bad_signature",
            Deny::NotYetValid => "not_yet_valid",
            Deny::Expired => "expired",
            Deny::WrongAudience => "wrong_audience",
            Deny::TtlTooLong => "ttl_too_long",
            Deny::Revoked => "revoked",
            Deny::RevocationMissing => "revocation_missing",
            Deny::RevocationStale => "revocation_stale",
            Deny::RevocationInvalid => "revocation_invalid",
            Deny::Widened => "widened",
            Deny::ParentMismatch => "parent_mismatch",
            Deny::TooManyBlocks => "too_many_blocks",
        }
    }
}

/// A successful verification: the effective claims (for a chain, after every block), the root token id and the chain length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Effective claims.
    pub claims: Claims,
    /// The id of the token (design A) or of the root (design C).
    pub token_id: String,
    /// 1 for design A; the root plus the blocks for design C.
    pub chain_len: usize,
}

/// The verifier's inputs besides the token: the node it is, the time, and the stated limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The node this verifier is (the token's audience must equal it).
    pub audience: String,
    /// The time, unix seconds. Supplied by the caller; the library never reads a clock.
    pub now: u64,
    /// `not_before` is accepted this many seconds early. Expiry has no grace.
    pub skew: u64,
    /// Longest `expiry - not_before` accepted.
    pub max_ttl: u64,
    /// A revocation list older than this many seconds denies (fail closed).
    pub rev_max_age: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            audience: String::new(),
            now: 0,
            skew: 30,
            max_ttl: 3600,
            rev_max_age: 300,
        }
    }
}

/// The issuer keys a verifier trusts, by key id.
#[derive(Debug, Clone, Default)]
pub struct Trust {
    keys: BTreeMap<String, String>,
}

impl Trust {
    /// Trust a public key (hex). Returns its key id, or an empty string when it is not a well-formed ML-DSA-65 key (then nothing is added).
    pub fn add(&mut self, pubkey_hex: &str) -> String {
        match key_id_of(pubkey_hex) {
            Some(id) => {
                self.keys.insert(id.clone(), pubkey_hex.to_string());
                id
            }
            None => String::new(),
        }
    }
    /// The public key for a key id.
    pub fn get(&self, key_id: &str) -> Option<&str> {
        self.keys.get(key_id).map(String::as_str)
    }
}

/// Lowercase hex: the first 8 bytes of BLAKE3 over the public key bytes; `None` unless the key is 1,952 bytes of lowercase hex.
pub fn key_id_of(pubkey_hex: &str) -> Option<String> {
    if pubkey_hex.len() != PUBKEY_HEX_LEN
        || !pubkey_hex
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let raw = hex::decode(pubkey_hex).ok()?;
    Some(hex::encode(&blake3::hash(&raw).as_bytes()[..8]))
}

/// The digest that is signed: domain separation by message kind, then the length and the canonical bytes.
pub fn digest(kind: &str, canonical: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-token-v1");
    h.update(&[0]);
    h.update(kind.as_bytes());
    h.update(&[0]);
    h.update(&(canonical.len() as u32).to_be_bytes());
    h.update(canonical);
    *h.finalize().as_bytes()
}

/// Verify a hex signature over a digest under a hex public key; the signature must have exactly the ML-DSA-65 length and lowercase hex.
pub fn sig_ok(pubkey_hex: &str, digest: &[u8; 32], sig_hex: &str) -> bool {
    sig_hex.len() == SIG_HEX_LEN
        && sig_hex
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        && key_id_of(pubkey_hex).is_some()
        && entropa_core::verify_hex(pubkey_hex, digest, sig_hex)
}

/// Time, audience and TTL rules on (effective) claims.
pub fn check_policy(c: &Claims, p: &Policy) -> Result<(), Deny> {
    if p.now.saturating_add(p.skew) < c.not_before {
        return Err(Deny::NotYetValid);
    }
    if p.now >= c.expiry {
        return Err(Deny::Expired);
    }
    if c.audience != p.audience {
        return Err(Deny::WrongAudience);
    }
    if c.expiry.saturating_sub(c.not_before) > p.max_ttl {
        return Err(Deny::TtlTooLong);
    }
    Ok(())
}
