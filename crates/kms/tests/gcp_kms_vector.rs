//! Google Cloud KMS ML-DSA-65 compatibility: responses recorded from the real service (2026-11-05, key
//! `entropa-ledger-signer` version 1) must parse, and the recorded signature must verify under Entropa's verifier.
#![cfg(feature = "gcp")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::{verify_hex, CheckpointSigner};
use entropa_kms::gcp::{
    parse_public_key_response, parse_sign_response, sign_request_body, GcpKmsConfig,
    PUBLIC_KEY_FORMAT,
};
use entropa_kms::{KeySpec, KmsClient, KmsError, KmsSigner};

const PK: &str = include_str!("vectors/gcp_publickey.json");
const SIG: &str = include_str!("vectors/gcp_sign.json");
const MSG: &[u8] = b"entropa test digest";

struct Recorded;
impl KmsClient for Recorded {
    fn public_key_raw(&self) -> Result<Vec<u8>, KmsError> {
        parse_public_key_response(PK)
    }
    fn sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, KmsError> {
        assert_eq!(msg, MSG);
        parse_sign_response(SIG)
    }
}

#[test]
fn g1_the_recorded_public_key_parses_to_1952_raw_bytes() {
    assert_eq!(parse_public_key_response(PK).unwrap().len(), 1952);
}

#[test]
fn g2_the_recorded_signature_verifies_under_entropas_verifier() {
    let s = KmsSigner::new(Recorded, KeySpec::MlDsa65).unwrap();
    let sig = s.try_sign_hex(MSG).unwrap();
    assert_eq!(sig.len(), 3309 * 2);
    assert!(
        verify_hex(&s.pubkey_hex(), MSG, &sig),
        "Google's ML-DSA signature must verify"
    );
    assert!(!verify_hex(&s.pubkey_hex(), b"another message", &sig));
}

#[test]
fn g3_malformed_responses_are_refused_without_echoing_them() {
    for bad in [
        "",
        "not json",
        "{}",
        r#"{"publicKey":{}}"#,
        r#"{"publicKey":{"data":"!!!"}}"#,
        r#"{"publicKey":{"data":"AAAA"}}"#,
    ] {
        assert!(parse_public_key_response(bad).is_err(), "{bad}");
    }
    for bad in [
        "",
        "{}",
        r#"{"signature":"!!!"}"#,
        r#"{"signature":"AAAA"}"#,
    ] {
        assert!(parse_sign_response(bad).is_err(), "{bad}");
    }
    let e = parse_public_key_response("secret-looking-text")
        .unwrap_err()
        .to_string();
    assert!(!e.contains("secret-looking"));
}

#[test]
fn g4_the_sign_request_carries_the_message_base64_and_the_public_key_format_is_pqc() {
    assert_eq!(
        sign_request_body(MSG),
        r#"{"data":"ZW50cm9wYSB0ZXN0IGRpZ2VzdA=="}"#
    );
    assert_eq!(PUBLIC_KEY_FORMAT, "NIST_PQC");
}

#[test]
fn g5_the_config_needs_a_key_version_and_rejects_anything_else() {
    let ok = GcpKmsConfig::from_vars(|k| {
        (k == "ENTROPA_GCP_KMS_KEY").then(|| {
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1".to_string()
        })
    })
    .unwrap();
    assert!(ok.key_version.ends_with("/cryptoKeyVersions/1"));
    assert!(GcpKmsConfig::from_vars(|_| None).is_err());
    assert!(GcpKmsConfig::from_vars(|_| Some("not-a-resource-name".into())).is_err());
    assert!(GcpKmsConfig::from_vars(|_| Some(
        "projects/p/locations/l/keyRings/r/cryptoKeys/k".into()
    ))
    .is_err());
}
