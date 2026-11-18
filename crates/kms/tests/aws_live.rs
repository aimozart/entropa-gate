//! Live test against the real AWS KMS key (stage S1). Ignored by default; runs only with
//! `--features aws -- --ignored` AND ENTROPA_KMS_KEY_ID set. Credentials come from the
//! standard environment variables only and are never printed.
//! Cost cap: 1 GetPublicKey + 3 Sign per run, about $0.0001.
#![cfg(feature = "aws")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_core::transparency_log::TransparencyLog;
use entropa_core::verify_hex;
use entropa_kms::aws::{AwsKmsClient, AwsKmsConfig};
use entropa_kms::{KeySpec, KmsClient, KmsError, KmsSigner};
use std::cell::Cell;

const VECTOR: &str = include_str!("vectors/aws_kms_ml_dsa_65.json");
const MAX_SIGNS: usize = 10;

fn vector_field(key: &str) -> String {
    let pat = format!("\"{key}\": \"");
    let start = VECTOR.find(&pat).unwrap() + pat.len();
    VECTOR[start..start + VECTOR[start..].find('"').unwrap()].to_string()
}

/// Counts requests so the cost cap is enforced, not just promised.
struct Counting<'a> {
    inner: AwsKmsClient,
    gets: &'a Cell<usize>,
    signs: &'a Cell<usize>,
}
impl KmsClient for Counting<'_> {
    fn public_key_raw(&self) -> Result<Vec<u8>, KmsError> {
        self.gets.set(self.gets.get() + 1);
        self.inner.public_key_raw()
    }
    fn sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, KmsError> {
        assert!(self.signs.get() < MAX_SIGNS, "sign cap reached");
        self.signs.set(self.signs.get() + 1);
        self.inner.sign_raw(msg)
    }
}

#[test]
#[ignore = "live AWS call: needs ENTROPA_KMS_KEY_ID and AWS_* credentials in the environment"]
fn three_checkpoints_signed_by_the_real_kms_key_verify() {
    let Ok(cfg) = AwsKmsConfig::from_vars(|k| std::env::var(k).ok()) else {
        eprintln!("ENTROPA_KMS_KEY_ID not set: skipping the live test");
        return;
    };
    let (gets, signs) = (Cell::new(0), Cell::new(0));
    let client = Counting {
        inner: AwsKmsClient::connect(&cfg).unwrap(),
        gets: &gets,
        signs: &signs,
    };
    let signer = KmsSigner::new(client, KeySpec::MlDsa65).unwrap();

    // The live key is the one captured in the offline vector.
    use entropa_core::CheckpointSigner;
    assert_eq!(signer.pubkey_hex(), vector_field("public_key_raw_hex"));

    let mut log = TransparencyLog::new();
    for (i, record) in [&b"live-1"[..], b"live-2", b"live-3"].iter().enumerate() {
        log.append(record);
        let cp = log.checkpoint_with(&signer, 1_000 + i as u64).unwrap();
        assert_eq!(cp.size, i + 1);
        assert!(cp.verify_signature(&signer.pubkey_hex()), "checkpoint {i}");
        assert!(!verify_hex(
            &cp.proposer_pubkey,
            b"unrelated",
            &cp.signature
        ));
    }
    println!(
        "live test OK: GetPublicKey requests = {}, Sign requests = {}",
        gets.get(),
        signs.get()
    );
    assert_eq!(gets.get(), 1);
    assert_eq!(signs.get(), 3);
}
