//! KMS-backed checkpoint signing.
//!
//! [`KmsSigner`] implements [`entropa_core::CheckpointSigner`] on top of any
//! [`KmsClient`], so Entropa can sign checkpoints with a managed ML-DSA key (for
//! example an AWS KMS `ML_DSA_65` key) while verifiers keep using plain
//! [`entropa_core::verify_hex`]. The client hides provider details (SPKI/DER key
//! encoding, request signing, auth), which keeps this crate testable with no cloud.

#[cfg(feature = "aws")]
pub mod aws;

#[cfg(feature = "gcp")]
pub mod gcp;

use entropa_core::signer::RAW_SIGN_LIMIT_BYTES;
use entropa_core::{CheckpointSigner, SignError};

/// Provider-side failure (network, permission, throttling, key disabled, ...).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("kms error: {0}")]
pub struct KmsError(pub String);

/// ML-DSA parameter sets a managed key can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySpec {
    /// ML-DSA-44 (FIPS 204 category 2).
    MlDsa44,
    /// ML-DSA-65 (category 3), the set Entropa verifies.
    MlDsa65,
    /// ML-DSA-87 (category 5).
    MlDsa87,
}

/// The minimal surface Entropa needs from a managed signing key.
pub trait KmsClient {
    /// Raw ML-DSA verifying-key bytes (the client strips any SPKI/DER wrapper).
    fn public_key_raw(&self) -> Result<Vec<u8>, KmsError>;
    /// Sign `msg` (raw message mode); returns the raw ML-DSA signature bytes.
    fn sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, KmsError>;
}

/// The fixed DER SubjectPublicKeyInfo prefix KMS puts in front of an ML-DSA-65 key.
pub const ML_DSA_65_SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
];
/// ML-DSA-65 raw verifying-key length in bytes.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// ML-DSA-65 signature length in bytes.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

/// Strip the SPKI wrapper KMS returns from `GetPublicKey`, yielding the raw 1952-byte
/// ML-DSA-65 key Entropa's verifiers use. Rejects any other prefix or length.
pub fn raw_key_from_spki(der: &[u8]) -> Result<Vec<u8>, KmsError> {
    let expected = ML_DSA_65_SPKI_PREFIX.len() + ML_DSA_65_PUBLIC_KEY_BYTES;
    if der.len() != expected {
        return Err(KmsError(format!(
            "unexpected public key length {} (expected {expected} for ML-DSA-65 SPKI)",
            der.len()
        )));
    }
    let (prefix, raw) = der.split_at(ML_DSA_65_SPKI_PREFIX.len());
    if prefix != ML_DSA_65_SPKI_PREFIX {
        return Err(KmsError("public key is not an ML-DSA-65 SPKI".into()));
    }
    Ok(raw.to_vec())
}

/// A checkpoint signer backed by a managed key.
pub struct KmsSigner<C: KmsClient> {
    client: C,
    pubkey_hex: String,
}

impl<C: KmsClient> KmsSigner<C> {
    /// Fetch and cache the public key. Only `MlDsa65` is accepted because that is the
    /// parameter set Entropa's verifiers use.
    pub fn new(client: C, spec: KeySpec) -> Result<Self, SignError> {
        if spec != KeySpec::MlDsa65 {
            return Err(SignError::Backend(format!(
                "unsupported key spec {spec:?}: Entropa verifiers use ML-DSA-65"
            )));
        }
        let raw = client
            .public_key_raw()
            .map_err(|e| SignError::Backend(e.to_string()))?;
        if raw.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
            return Err(SignError::Backend(format!(
                "public key is {} bytes, expected {ML_DSA_65_PUBLIC_KEY_BYTES} for ML-DSA-65",
                raw.len()
            )));
        }
        Ok(Self {
            client,
            pubkey_hex: hex::encode(raw),
        })
    }
}

impl<C: KmsClient> CheckpointSigner for KmsSigner<C> {
    fn algorithm(&self) -> &'static str {
        "ML-DSA-65"
    }
    fn pubkey_hex(&self) -> String {
        self.pubkey_hex.clone()
    }
    fn try_sign_hex(&self, msg: &[u8]) -> Result<String, SignError> {
        if msg.len() > RAW_SIGN_LIMIT_BYTES {
            return Err(SignError::Backend(format!(
                "message of {} bytes exceeds the {RAW_SIGN_LIMIT_BYTES}-byte raw signing limit",
                msg.len()
            )));
        }
        let sig = self
            .client
            .sign_raw(msg)
            .map_err(|e| SignError::Backend(e.to_string()))?;
        if sig.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err(SignError::Backend(format!(
                "signature is {} bytes, expected {ML_DSA_65_SIGNATURE_BYTES} for ML-DSA-65",
                sig.len()
            )));
        }
        Ok(hex::encode(sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entropa_core::transparency_log::TransparencyLog;
    use entropa_core::{verify_hex, Probe};
    use std::cell::Cell;

    /// Mock managed key: a Probe behind the client interface; counts sign calls.
    struct FakeKms {
        key: Probe,
        sign_calls: Cell<usize>,
        fail_pubkey: bool,
        fail_sign: bool,
    }
    impl FakeKms {
        fn ok() -> Self {
            Self {
                key: Probe::spawn(),
                sign_calls: Cell::new(0),
                fail_pubkey: false,
                fail_sign: false,
            }
        }
    }
    impl KmsClient for &FakeKms {
        fn public_key_raw(&self) -> Result<Vec<u8>, KmsError> {
            if self.fail_pubkey {
                return Err(KmsError("AccessDenied".into()));
            }
            Ok(hex::decode(self.key.pubkey_hex()).unwrap())
        }
        fn sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, KmsError> {
            self.sign_calls.set(self.sign_calls.get() + 1);
            if self.fail_sign {
                return Err(KmsError("ThrottlingException".into()));
            }
            Ok(hex::decode(self.key.sign_hex(msg)).unwrap())
        }
    }

    #[test]
    fn raw_key_from_spki_strips_the_22_byte_wrapper() {
        let mut der = ML_DSA_65_SPKI_PREFIX.to_vec();
        der.extend(vec![7u8; ML_DSA_65_PUBLIC_KEY_BYTES]);
        let raw = raw_key_from_spki(&der).unwrap();
        assert_eq!(raw.len(), ML_DSA_65_PUBLIC_KEY_BYTES);
        assert!(raw.iter().all(|b| *b == 7));
    }

    #[test]
    fn raw_key_from_spki_rejects_a_wrong_prefix_or_length() {
        let mut bad_prefix = vec![0u8; 22];
        bad_prefix.extend(vec![7u8; ML_DSA_65_PUBLIC_KEY_BYTES]);
        assert!(raw_key_from_spki(&bad_prefix).is_err());
        let mut short = ML_DSA_65_SPKI_PREFIX.to_vec();
        short.extend(vec![7u8; 100]);
        assert!(raw_key_from_spki(&short).is_err());
        assert!(raw_key_from_spki(&[]).is_err());
    }

    #[test]
    fn new_caches_the_public_key_and_reports_ml_dsa_65() {
        let k = FakeKms::ok();
        let s = KmsSigner::new(&k, KeySpec::MlDsa65).unwrap();
        assert_eq!(s.pubkey_hex(), k.key.pubkey_hex());
        assert_eq!(s.algorithm(), "ML-DSA-65");
    }

    #[test]
    fn a_checkpoint_signed_through_kms_verifies_with_plain_verify_hex() {
        let k = FakeKms::ok();
        let s = KmsSigner::new(&k, KeySpec::MlDsa65).unwrap();
        let mut log = TransparencyLog::new();
        log.append(b"a");
        let cp = log.checkpoint_with(&s, 5).unwrap();
        assert_eq!(k.sign_calls.get(), 1);
        assert!(cp.verify_signature(&k.key.pubkey_hex()));
        let digest_sig_ok = verify_hex(&cp.proposer_pubkey, b"unrelated", &cp.signature);
        assert!(
            !digest_sig_ok,
            "signature must not verify an unrelated message"
        );
    }

    #[test]
    fn a_sign_failure_becomes_a_backend_error_and_leaves_the_log_unchanged() {
        let mut k = FakeKms::ok();
        k.fail_sign = true;
        let s = KmsSigner::new(&k, KeySpec::MlDsa65).unwrap();
        let mut log = TransparencyLog::new();
        log.append(b"a");
        let before = (log.len(), log.root());
        let err = log.checkpoint_with(&s, 5).unwrap_err();
        assert!(matches!(&err, SignError::Backend(m) if m.contains("ThrottlingException")));
        assert_eq!((log.len(), log.root()), before);
    }

    #[test]
    fn a_public_key_fetch_failure_fails_construction() {
        let mut k = FakeKms::ok();
        k.fail_pubkey = true;
        let err = KmsSigner::new(&k, KeySpec::MlDsa65).err().unwrap();
        assert!(matches!(&err, SignError::Backend(m) if m.contains("AccessDenied")));
    }

    #[test]
    fn other_parameter_sets_are_rejected_because_verifiers_use_ml_dsa_65() {
        let k = FakeKms::ok();
        for spec in [KeySpec::MlDsa44, KeySpec::MlDsa87] {
            let err = KmsSigner::new(&k, spec).err().unwrap();
            assert!(matches!(&err, SignError::Backend(m) if m.contains("unsupported")));
        }
    }

    #[test]
    fn a_message_over_the_raw_limit_is_rejected_without_calling_the_backend() {
        let k = FakeKms::ok();
        let s = KmsSigner::new(&k, KeySpec::MlDsa65).unwrap();
        let big = vec![0u8; RAW_SIGN_LIMIT_BYTES + 1];
        assert!(s.try_sign_hex(&big).is_err());
        assert_eq!(k.sign_calls.get(), 0);
    }

    /// Client whose key/signature bytes are scripted, to probe how KmsSigner trusts its client.
    struct ScriptedKms {
        pubkey: Vec<u8>,
        sig: Vec<u8>,
    }
    impl KmsClient for ScriptedKms {
        fn public_key_raw(&self) -> Result<Vec<u8>, KmsError> {
            Ok(self.pubkey.clone())
        }
        fn sign_raw(&self, _msg: &[u8]) -> Result<Vec<u8>, KmsError> {
            Ok(self.sig.clone())
        }
    }

    #[test]
    fn audit_a_wrong_length_public_key_from_the_client_is_rejected_at_construction() {
        let c = ScriptedKms {
            pubkey: vec![1u8; 100],
            sig: vec![],
        };
        assert!(KmsSigner::new(c, KeySpec::MlDsa65).is_err());
    }

    #[test]
    fn audit_a_wrong_length_signature_from_the_client_is_rejected() {
        let k = FakeKms::ok();
        let c = ScriptedKms {
            pubkey: hex::decode(k.key.pubkey_hex()).unwrap(),
            sig: vec![0u8; 10],
        };
        let s = KmsSigner::new(c, KeySpec::MlDsa65).unwrap();
        assert!(s.try_sign_hex(b"m").is_err());
    }

    #[test]
    fn audit_checkpoint_with_rejects_a_signature_that_does_not_verify_under_the_reported_pubkey() {
        let k = FakeKms::ok();
        let other = Probe::spawn();
        let c = ScriptedKms {
            pubkey: hex::decode(k.key.pubkey_hex()).unwrap(),
            sig: hex::decode(other.sign_hex(b"x")).unwrap(),
        };
        let s = KmsSigner::new(c, KeySpec::MlDsa65).unwrap();
        let mut log = TransparencyLog::new();
        log.append(b"a");
        assert!(log.checkpoint_with(&s, 5).is_err());
    }

    #[test]
    fn audit_guard_empty_log_checkpoint_signs_and_verifies() {
        let k = FakeKms::ok();
        let s = KmsSigner::new(&k, KeySpec::MlDsa65).unwrap();
        let cp = TransparencyLog::new().checkpoint_with(&s, 5).unwrap();
        assert_eq!(cp.size, 0);
        assert!(cp.verify_signature(&k.key.pubkey_hex()));
    }

    #[test]
    fn audit_guard_empty_log_and_one_empty_record_have_the_same_root_but_different_signed_digests()
    {
        let k = FakeKms::ok();
        let s = KmsSigner::new(&k, KeySpec::MlDsa65).unwrap();
        let empty = TransparencyLog::new().checkpoint_with(&s, 5).unwrap();
        let mut one = TransparencyLog::new();
        one.append(b"");
        let one_cp = one.checkpoint_with(&s, 5).unwrap();
        assert_eq!(empty.root, one_cp.root);
        assert_ne!(empty.signature, one_cp.signature);
    }

    #[test]
    fn audit_guard_max_timestamp_and_message_exactly_at_the_limit() {
        let k = FakeKms::ok();
        let s = KmsSigner::new(&k, KeySpec::MlDsa65).unwrap();
        let mut log = TransparencyLog::new();
        log.append(b"a");
        let cp = log.checkpoint_with(&s, u64::MAX).unwrap();
        assert!(cp.verify_signature(&k.key.pubkey_hex()));
        assert!(s.try_sign_hex(&vec![0u8; RAW_SIGN_LIMIT_BYTES]).is_ok());
        assert!(s.try_sign_hex(&[]).is_ok());
    }

    #[test]
    fn audit_guard_spki_edges_one_flipped_prefix_bit_and_off_by_one_lengths() {
        let mut der = ML_DSA_65_SPKI_PREFIX.to_vec();
        der.extend(vec![7u8; ML_DSA_65_PUBLIC_KEY_BYTES]);
        let mut flipped = der.clone();
        flipped[21] ^= 1;
        assert!(raw_key_from_spki(&flipped).is_err());
        let mut longer = der.clone();
        longer.push(0);
        assert!(raw_key_from_spki(&longer).is_err());
        assert!(raw_key_from_spki(&der[..der.len() - 1]).is_err());
        assert!(raw_key_from_spki(&ML_DSA_65_SPKI_PREFIX).is_err());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(16))]
        /// CheckpointSigner round-trip: any log contents and timestamp signed through a
        /// KmsSigner verify under the reported pubkey and fail under another key.
        #[test]
        fn prop_kms_signed_checkpoints_always_verify(
            recs in proptest::collection::vec(proptest::collection::vec(proptest::prelude::any::<u8>(), 0..16), 0..20),
            ts in proptest::prelude::any::<u64>(),
        ) {
            let k = FakeKms::ok();
            let s = KmsSigner::new(&k, KeySpec::MlDsa65).unwrap();
            let mut log = TransparencyLog::new();
            for r in &recs { log.append(r); }
            let cp = log.checkpoint_with(&s, ts).unwrap();
            proptest::prop_assert_eq!(cp.size, recs.len());
            proptest::prop_assert!(cp.verify_signature(&s.pubkey_hex()));
            proptest::prop_assert!(!cp.verify_signature(&Probe::spawn().pubkey_hex()));
        }
    }
}

/// Compiles and runs the README quickstart as a doc test.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
