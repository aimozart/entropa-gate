//! Evidence test: a signature produced by a real AWS KMS ML_DSA_65 key verifies under
//! Entropa's own verifier. The vector was captured once from KMS (see the JSON) so this
//! test runs offline and costs nothing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_core::verify_hex;

fn field(json: &str, key: &str) -> String {
    let pat = format!("\"{key}\": \"");
    let start = json.find(&pat).expect(key) + pat.len();
    json[start..start + json[start..].find('"').unwrap()].to_string()
}

const VECTOR: &str = include_str!("vectors/aws_kms_ml_dsa_65.json");

#[test]
fn a_real_kms_signature_verifies_with_entropas_verifier() {
    let pk = field(VECTOR, "public_key_raw_hex");
    let msg = hex::decode(field(VECTOR, "message_hex")).unwrap();
    let sig = field(VECTOR, "signature_hex");
    assert_eq!(pk.len() / 2, 1952, "ML-DSA-65 verifying key size");
    assert_eq!(sig.len() / 2, 3309, "ML-DSA-65 signature size");
    assert!(verify_hex(&pk, &msg, &sig));
}

#[test]
fn the_kms_signature_does_not_verify_a_different_message() {
    let pk = field(VECTOR, "public_key_raw_hex");
    let sig = field(VECTOR, "signature_hex");
    assert!(!verify_hex(&pk, b"a different message", &sig));
}

#[test]
fn spki_wrapper_is_the_22_byte_prefix_before_the_raw_key() {
    let prefix = field(VECTOR, "spki_prefix_hex");
    assert_eq!(prefix.len() / 2, 22);
    assert!(prefix.starts_with("308207b2300b0609608648016503040312"));
}
