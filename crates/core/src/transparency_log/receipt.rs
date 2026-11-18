//! What a customer actually receives from a submission, and verifies independently.

use crate::merkle::{self, ProofStep};
use crate::transparency_log::Checkpoint;

/// What a customer actually receives and can independently verify: a record, its
/// inclusion proof, and the checkpoint the proof is anchored to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Receipt {
    /// Position of the record in the log.
    pub index: usize,
    /// The record bytes proven to be included.
    #[serde(with = "hex_bytes")]
    pub record: Vec<u8>,
    /// Inclusion proof from the record's leaf to the checkpoint root.
    pub proof: Vec<ProofStep>,
    /// The signed checkpoint the proof is verified against.
    pub checkpoint: Checkpoint,
}

/// Serializes a byte record as a hex string instead of a raw JSON number array,
/// matching this project's existing hash-formatting convention — and, unlike a raw
/// byte array, lets a customer (or a test) see and reason about the actual wire bytes.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Independent verification — a customer runs this themselves, trusting only the
/// signer's pubkey (obtained out-of-band, e.g. published on Entropa's own site), not
/// any of Entropa's own server-side "verified" claims. The receipt's `index` and the
/// checkpoint's `size` are bound to the proof path (RFC 6962 inclusion rules): a proof
/// verifies only at the position and tree size it was built for.
pub fn verify_receipt(receipt: &Receipt, expected_pubkey_hex: &str) -> bool {
    if !receipt.checkpoint.verify_signature(expected_pubkey_hex) {
        return false;
    }
    let leaf = merkle::leaf_hash(&receipt.record);
    merkle::verify_inclusion_at(
        &leaf,
        receipt.index,
        receipt.checkpoint.size,
        &receipt.proof,
        &receipt.checkpoint.root,
    )
}

#[cfg(test)]
mod tests {
    fn log_of(n: usize) -> TransparencyLog {
        let mut log = TransparencyLog::new();
        for i in 0..n {
            log.append(format!("record-{i}").as_bytes());
        }
        log
    }

    /// S0g: the index and tree size are bound to the proof (RFC 6962/9162 inclusion rules).
    #[test]
    fn verify_receipt_rejects_a_receipt_whose_index_does_not_match_its_proof() {
        let log = log_of(4);
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        let mut receipt = log.receipt(1, &checkpoint).unwrap();
        assert!(verify_receipt(&receipt, &p.pubkey_hex()));
        receipt.index = 2; // same record, same proof, wrong claimed position
        assert!(!verify_receipt(&receipt, &p.pubkey_hex()));
    }

    #[test]
    fn verify_receipt_rejects_an_index_at_or_beyond_the_checkpoint_size() {
        let log = log_of(4);
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        let mut receipt = log.receipt(3, &checkpoint).unwrap();
        for bad in [4usize, 5, usize::MAX] {
            receipt.index = bad;
            assert!(!verify_receipt(&receipt, &p.pubkey_hex()), "index {bad}");
        }
    }

    /// A correctly SIGNED checkpoint that claims a different tree size than the proof was
    /// built for must not verify: the size shapes the audit path.
    #[test]
    fn verify_receipt_rejects_a_signed_checkpoint_with_the_wrong_tree_size() {
        let log = log_of(4);
        let p = probe();
        let good = log.checkpoint(&p, 1_000);
        let mut receipt = log.receipt(1, &good).unwrap();
        let wrong_size = 5usize; // different audit-path shape for index 1 (size 3 has the same shape)
        let digest =
            crate::transparency_log::checkpoint_digest_for_tests(&good.root, wrong_size, 1_000);
        receipt.checkpoint.size = wrong_size;
        receipt.checkpoint.signature = p.sign_hex(&digest);
        assert!(
            receipt.checkpoint.verify_signature(&p.pubkey_hex()),
            "setup: signature is valid"
        );
        assert!(!verify_receipt(&receipt, &p.pubkey_hex()));
    }

    #[test]
    fn verify_receipt_accepts_every_index_of_every_size_up_to_17() {
        let p = probe();
        for n in 1..=17 {
            let log = log_of(n);
            let checkpoint = log.checkpoint(&p, 1_000);
            for i in 0..n {
                let receipt = log.receipt(i, &checkpoint).unwrap();
                assert!(
                    verify_receipt(&receipt, &p.pubkey_hex()),
                    "size {n} index {i}"
                );
            }
        }
    }

    use super::*;
    use crate::pqc::Probe;
    use crate::transparency_log::TransparencyLog;

    fn probe() -> Probe {
        Probe::spawn()
    }

    #[test]
    fn verify_receipt_rejects_a_forged_record() {
        let mut log = TransparencyLog::new();
        log.append(b"real");
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        let mut receipt = log.receipt(0, &checkpoint).unwrap();
        receipt.record = b"forged".to_vec();
        assert!(!verify_receipt(&receipt, &p.pubkey_hex()));
    }

    #[test]
    fn verify_receipt_rejects_a_tampered_proof() {
        let mut log = TransparencyLog::new();
        log.append(b"a");
        log.append(b"b");
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        let mut receipt = log.receipt(0, &checkpoint).unwrap();
        receipt.proof[0].sibling = merkle::leaf_hash(b"tampered-sibling");
        assert!(!verify_receipt(&receipt, &p.pubkey_hex()));
    }

    #[test]
    fn verify_receipt_rejects_a_checkpoint_from_a_different_signer() {
        let mut log = TransparencyLog::new();
        log.append(b"a");
        let real_signer = probe();
        let checkpoint = log.checkpoint(&real_signer, 1_000);
        let receipt = log.receipt(0, &checkpoint).unwrap();
        let impostor = probe();
        assert!(!verify_receipt(&receipt, &impostor.pubkey_hex()));
    }

    /// A customer receives this over JSON (the actual wire format) -- a round trip
    /// through serde must preserve everything `verify_receipt` needs, hex-encoded
    /// hashes included, not just work in-process.
    #[test]
    fn receipt_survives_a_real_json_round_trip_and_still_verifies() {
        let mut log = TransparencyLog::new();
        log.append(b"real-payload");
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        let receipt = log.receipt(0, &checkpoint).unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(
            json.contains(&hex::encode(receipt.checkpoint.root)),
            "root must be hex-encoded in the JSON, not a raw byte array"
        );
        let restored: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, receipt);
        assert!(verify_receipt(&restored, &p.pubkey_hex()));
    }
}
