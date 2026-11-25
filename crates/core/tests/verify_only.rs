#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! BV1: the verification path works with the `signing` feature OFF (no randomness source, builds for wasm32). Known vectors: a fixed 32-byte test seed (a public test value, not a key anyone uses),
//! a signature over a fixed message, and a one-record log receipt. Regenerate with `VERIFY_VECTOR_WRITE=1 cargo test -p entropa-core --test verify_only -- --ignored` (needs the default `signing` feature). Synthetic data only.
use entropa_core::transparency_log::{verify_receipt, Receipt};
use entropa_core::verify_hex;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/verify_only.json");

fn v() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}
fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap().to_string()
}

#[test]
fn a_known_signature_verifies_and_a_changed_message_or_key_does_not() {
    let d = v();
    assert!(verify_hex(
        &s(&d, "pubkey"),
        s(&d, "message").as_bytes(),
        &s(&d, "signature")
    ));
    assert!(!verify_hex(
        &s(&d, "pubkey"),
        b"another message",
        &s(&d, "signature")
    ));
    let mut bad = s(&d, "signature");
    bad.replace_range(0..2, if &bad[0..2] == "00" { "01" } else { "00" });
    assert!(!verify_hex(
        &s(&d, "pubkey"),
        s(&d, "message").as_bytes(),
        &bad
    ));
}

#[test]
fn a_known_receipt_verifies_only_under_its_own_key_and_unchanged() {
    let d = v();
    let r: Receipt = serde_json::from_value(d["receipt"].clone()).unwrap();
    assert!(verify_receipt(&r, &s(&d, "pubkey")));
    let mut changed = r.clone();
    changed.record.push(b'!');
    assert!(!verify_receipt(&changed, &s(&d, "pubkey")));
    let mut other = s(&d, "pubkey");
    other.replace_range(0..2, if &other[0..2] == "00" { "01" } else { "00" });
    assert!(!verify_receipt(&r, &other));
}

#[cfg(feature = "signing")]
#[test]
#[ignore = "writes tests/vectors/verify_only.json; run only on purpose"]
fn write_the_vector() {
    use entropa_core::transparency_log::TransparencyLog;
    use entropa_core::Probe;
    if std::env::var("VERIFY_VECTOR_WRITE").is_err() {
        return;
    }
    let seed = hex::encode([7u8; 32]);
    let p = Probe::from_signing_key_hex(&seed).unwrap();
    let message = "entropa verify-only vector 1";
    let mut log = TransparencyLog::new();
    log.append(b"synthetic record one");
    let cp = log.checkpoint(&p, 1_700_000_000);
    let receipt = log.receipt(0, &cp).unwrap();
    let out = serde_json::json!({"seed_note": "seed is 32 bytes of 0x07, a public test value", "pubkey": p.pubkey_hex(), "message": message, "signature": p.sign_hex(message.as_bytes()), "receipt": receipt});
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/verify_only.json"
        ),
        serde_json::to_string_pretty(&out).unwrap() + "\n",
    )
    .unwrap();
}
