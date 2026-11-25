//! The signed statement of a log's state at a point in time.

use crate::merkle::Hash;

pub(super) fn checkpoint_digest(root: &Hash, size: usize, timestamp: u64) -> Vec<u8> {
    let mut digest = Vec::with_capacity(32 + 16);
    digest.extend_from_slice(root);
    digest.extend_from_slice(&(size as u64).to_be_bytes());
    digest.extend_from_slice(&timestamp.to_be_bytes());
    digest
}

/// A signed statement of the log's state at a point in time — what an inclusion proof
/// is actually verified against, and what would be externally anchored periodically.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    #[serde(with = "crate::merkle::hex_hash")]
    /// Merkle root at `size` (the empty log reports the hash of the empty leaf).
    pub root: Hash,
    /// Number of records covered.
    pub size: usize,
    /// Caller-supplied timestamp, signed with the root and size.
    pub timestamp: u64,
    /// Hex ML-DSA verifying key of the signer.
    pub proposer_pubkey: String,
    /// Hex ML-DSA signature over root, size and timestamp.
    pub signature: String,
}

impl Checkpoint {
    /// Verify this checkpoint's signature against a claimed signer's pubkey. Checks
    /// both that the signature is valid *and* that it was produced by the pubkey the
    /// checkpoint itself claims — a caller comparing against a pubkey they already
    /// trust (not just whatever the checkpoint says) is what actually matters.
    pub fn verify_signature(&self, expected_pubkey_hex: &str) -> bool {
        if self.proposer_pubkey != expected_pubkey_hex {
            return false;
        }
        let digest = checkpoint_digest(&self.root, self.size, self.timestamp);
        crate::pqc::verify_hex(expected_pubkey_hex, &digest, &self.signature)
    }
}

#[cfg(all(test, feature = "signing"))]
mod tests {
    /// Golden layout: root (32) || size as u64 big-endian (8) || timestamp u64 big-endian (8),
    /// identical on 32- and 64-bit targets.
    #[test]
    fn checkpoint_digest_has_a_fixed_width_golden_layout() {
        let root = [0xabu8; 32];
        let d = super::checkpoint_digest(&root, 7, 9);
        assert_eq!(d.len(), 48);
        assert_eq!(&d[..32], &root);
        assert_eq!(&d[32..40], &[0, 0, 0, 0, 0, 0, 0, 7]);
        assert_eq!(&d[40..], &[0, 0, 0, 0, 0, 0, 0, 9]);
    }

    use crate::pqc::Probe;
    use crate::transparency_log::TransparencyLog;

    fn probe() -> Probe {
        Probe::spawn()
    }

    #[test]
    fn checkpoint_signature_verifies_against_the_signing_probe() {
        let mut log = TransparencyLog::new();
        log.append(b"a");
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        assert!(checkpoint.verify_signature(&p.pubkey_hex()));
    }

    #[test]
    fn checkpoint_signature_rejects_a_different_probes_pubkey() {
        let mut log = TransparencyLog::new();
        log.append(b"a");
        let p = probe();
        let other = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        assert!(!checkpoint.verify_signature(&other.pubkey_hex()));
    }

    #[test]
    fn checkpoint_signature_rejects_a_tampered_root() {
        let mut log = TransparencyLog::new();
        log.append(b"a");
        let p = probe();
        let mut checkpoint = log.checkpoint(&p, 1_000);
        checkpoint.root = crate::merkle::leaf_hash(b"tampered");
        assert!(!checkpoint.verify_signature(&p.pubkey_hex()));
    }
}
