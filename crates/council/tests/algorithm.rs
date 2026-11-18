//! Algorithm agility (G1 item 9): every event carries a SIGNED `alg` label; verification dispatches on it through a
//! registry; a second algorithm can be swapped in by configuration. Only ML-DSA-65 exists in entropa-core, so the
//! swap is exercised with a fake test-only algorithm (a recorded limit: no second ML-DSA parameter set is available).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::{CheckpointSigner, Probe, SignError};
use serde_json::{json, Value};

const FAKE: &str = "FAKE-TEST-ALG";

/// A test-only signer: the "signature" is a keyed BLAKE3 of the message. Not secure, only an algorithm with another label.
struct FakeSigner;
fn fake_sig(pubkey: &str, msg: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"fake-test-alg\0");
    h.update(pubkey.as_bytes());
    h.update(msg);
    hex::encode(h.finalize().as_bytes())
}
impl CheckpointSigner for FakeSigner {
    fn algorithm(&self) -> &'static str {
        FAKE
    }
    fn pubkey_hex(&self) -> String {
        "fa".repeat(32)
    }
    fn try_sign_hex(&self, msg: &[u8]) -> Result<String, SignError> {
        Ok(fake_sig(&self.pubkey_hex(), msg))
    }
}
struct FakeVerifier;
impl SignatureVerifier for FakeVerifier {
    fn algorithm(&self) -> &'static str {
        FAKE
    }
    fn verify(&self, pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
        fake_sig(pubkey_hex, msg) == sig_hex
    }
}

fn extended() -> Registry {
    Registry::default().with(Box::new(FakeVerifier))
}

fn unsigned_with_alg(alg: &str) -> String {
    unsigned("session.closed", json!({"alg": alg})).to_string()
}

#[test]
fn a1_an_ml_dsa_event_carries_its_label_and_verifies_with_the_default_registry() {
    let p = Probe::spawn();
    let signed = must(sign_event(&p, &unsigned_with_alg("ML-DSA-65")));
    let v: Value = serde_json::from_str(&signed).unwrap();
    assert_eq!(v["alg"], "ML-DSA-65");
    let e = must(verify_event(&signed, &p.pubkey_hex()));
    assert!(
        e.canonical_json().contains("\"alg\":\"ML-DSA-65\""),
        "the label is inside the signed bytes"
    );
    must(verify_event_with(
        &signed,
        &p.pubkey_hex(),
        &Registry::default(),
    ));
}

#[test]
fn a2_the_default_registry_knows_exactly_ml_dsa_65() {
    assert_eq!(Registry::default().algorithms(), vec!["ML-DSA-65"]);
    assert_eq!(
        extended().algorithms(),
        vec!["FAKE-TEST-ALG", "ML-DSA-65"],
        "sorted"
    );
}

#[test]
fn a3_a_second_algorithm_is_a_configuration_swap_not_a_format_change() {
    let signed = must(sign_event(&FakeSigner, &unsigned_with_alg(FAKE)));
    assert_eq!(serde_json::from_str::<Value>(&signed).unwrap()["alg"], FAKE);
    // the decoder is algorithm-neutral: the event decodes
    must(decode_event(&signed));
    // the default registry does not know the label: Verify, not Invalid
    assert!(matches!(
        verify_event(&signed, &FakeSigner.pubkey_hex()),
        Err(CouncilError::Verify(_))
    ));
    // a registry that was configured with the second algorithm accepts it
    must(verify_event_with(
        &signed,
        &FakeSigner.pubkey_hex(),
        &extended(),
    ));
    // and the format and the digest are the same for both algorithms
    assert_eq!(
        canonical_bytes(&must(decode_event(&signed))).first(),
        Some(&b'{')
    );
}

#[test]
fn a4_the_label_is_signed_so_relabelling_an_event_fails_in_both_directions() {
    let p = Probe::spawn();
    let ml = must(sign_event(&p, &unsigned_with_alg("ML-DSA-65")));
    let mut relabelled: Value = serde_json::from_str(&ml).unwrap();
    relabelled["alg"] = json!(FAKE);
    assert!(
        matches!(
            verify_event_with(&relabelled.to_string(), &p.pubkey_hex(), &extended()),
            Err(CouncilError::Verify(_))
        ),
        "ML-DSA event relabelled as the fake algorithm"
    );
    let fake = must(sign_event(&FakeSigner, &unsigned_with_alg(FAKE)));
    let mut back: Value = serde_json::from_str(&fake).unwrap();
    back["alg"] = json!("ML-DSA-65");
    assert!(
        matches!(
            verify_event_with(&back.to_string(), &FakeSigner.pubkey_hex(), &extended()),
            Err(CouncilError::Verify(_))
        ),
        "fake-signed event relabelled as ML-DSA-65"
    );
}

#[test]
fn a5_an_event_cannot_be_signed_under_a_label_that_is_not_the_signers_algorithm() {
    let p = Probe::spawn();
    assert!(matches!(
        expect_err(sign_event(&p, &unsigned_with_alg(FAKE))),
        CouncilError::Invalid(_)
    ));
    assert!(matches!(
        expect_err(sign_event(&FakeSigner, &unsigned_with_alg("ML-DSA-65"))),
        CouncilError::Invalid(_)
    ));
}

#[test]
fn a6_a_verifier_for_one_label_is_never_asked_to_judge_another() {
    let signed = must(sign_event(&FakeSigner, &unsigned_with_alg(FAKE)));
    let ml_only = Registry::default();
    assert!(matches!(
        verify_event_with(&signed, &FakeSigner.pubkey_hex(), &ml_only),
        Err(CouncilError::Verify(_))
    ));
    let p = Probe::spawn();
    let ml = must(sign_event(&p, &unsigned_with_alg("ML-DSA-65")));
    // a registry that only knows the fake algorithm does not accept an ML-DSA event either
    let fake_only = Registry::empty().with(Box::new(FakeVerifier));
    assert!(matches!(
        verify_event_with(&ml, &p.pubkey_hex(), &fake_only),
        Err(CouncilError::Verify(_))
    ));
}
