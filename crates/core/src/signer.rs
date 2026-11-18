//! Pluggable checkpoint signing backends.
//!
//! The log signs each checkpoint through [`CheckpointSigner`], so the key can live
//! in-process (a [`Probe`]) or behind a managed service such as an HSM-backed cloud
//! KMS key. Every backend must produce ML-DSA signatures that verify with
//! [`crate::verify_hex`] against the pubkey it reports, so verifiers never need to
//! know which backend signed.

use crate::pqc::Probe;

/// A signing backend failed (network, permission, throttling, ...). The log is left
/// unchanged when this happens; the caller decides whether to retry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The backend reported a failure (or returned output that failed validation).
    #[error("signing backend failed: {0}")]
    Backend(String),
}

/// Anything that can sign a checkpoint digest with ML-DSA.
pub trait CheckpointSigner {
    /// Short algorithm label, e.g. `"ML-DSA-65"`.
    fn algorithm(&self) -> &'static str;
    /// Hex verifying key that verifies this backend's signatures.
    fn pubkey_hex(&self) -> String;
    /// Sign `msg`, returning a hex signature, or why the backend could not.
    fn try_sign_hex(&self, msg: &[u8]) -> Result<String, SignError>;
}

/// KMS-style backends accept raw messages only up to this size (AWS KMS: 4 KB);
/// checkpoint digests must stay far below it.
pub const RAW_SIGN_LIMIT_BYTES: usize = 4096;

impl CheckpointSigner for Probe {
    fn algorithm(&self) -> &'static str {
        "ML-DSA-65"
    }
    fn pubkey_hex(&self) -> String {
        Probe::pubkey_hex(self)
    }
    fn try_sign_hex(&self, msg: &[u8]) -> Result<String, SignError> {
        Ok(self.sign_hex(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparency_log::TransparencyLog;
    use std::cell::Cell;

    /// A stand-in for a remote key: wraps a Probe, counts calls, can be told to fail.
    struct FakeRemote {
        inner: Probe,
        calls: Cell<usize>,
        fail: bool,
    }
    impl CheckpointSigner for FakeRemote {
        fn algorithm(&self) -> &'static str {
            "ML-DSA-65"
        }
        fn pubkey_hex(&self) -> String {
            self.inner.pubkey_hex()
        }
        fn try_sign_hex(&self, msg: &[u8]) -> Result<String, SignError> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                return Err(SignError::Backend("throttled".into()));
            }
            Ok(self.inner.sign_hex(msg))
        }
    }
    fn remote(fail: bool) -> FakeRemote {
        FakeRemote {
            inner: Probe::spawn(),
            calls: Cell::new(0),
            fail,
        }
    }

    #[test]
    fn a_probe_reports_its_algorithm_and_signs_through_the_trait() {
        let p = Probe::spawn();
        assert_eq!(CheckpointSigner::algorithm(&p), "ML-DSA-65");
        let sig = p.try_sign_hex(b"m").unwrap();
        assert!(crate::verify_hex(&p.pubkey_hex(), b"m", &sig));
        assert_eq!(
            CheckpointSigner::pubkey_hex(&p),
            Probe::pubkey_hex(&p),
            "trait pubkey must be the probe's real key"
        );
        assert_eq!(CheckpointSigner::pubkey_hex(&p).len(), 1952 * 2);
    }

    #[test]
    fn checkpoint_with_a_remote_backend_verifies_under_its_pubkey() {
        let mut log = TransparencyLog::new();
        log.append(b"a");
        let r = remote(false);
        let cp = log.checkpoint_with(&r, 1_000).unwrap();
        assert_eq!(r.calls.get(), 1);
        assert!(cp.verify_signature(&r.pubkey_hex()));
        assert_eq!(cp.size, 1);
        assert_eq!(cp.proposer_pubkey, r.pubkey_hex());
    }

    #[test]
    fn a_failing_backend_returns_an_error_and_leaves_the_log_unchanged() {
        let mut log = TransparencyLog::new();
        log.append(b"a");
        let before = (log.len(), log.root());
        let r = remote(true);
        let err = log.checkpoint_with(&r, 1_000).unwrap_err();
        assert_eq!(err, SignError::Backend("throttled".into()));
        assert_eq!((log.len(), log.root()), before);
    }

    #[test]
    fn the_checkpoint_digest_fits_a_kms_raw_signing_limit() {
        let root = crate::merkle::leaf_hash(b"x");
        let digest = crate::transparency_log::checkpoint_digest_for_tests(&root, 7, 9);
        assert!(digest.len() < RAW_SIGN_LIMIT_BYTES);
    }
}
