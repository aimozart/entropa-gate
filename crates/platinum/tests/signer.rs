//! The node signs with a pluggable signer (a managed KMS key in the cloud, the key file locally). Here a second
//! Probe stands in for the remote key: events and checkpoints must verify under ITS public key, not the file key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::{CheckpointSigner, Probe};
use entropa_platinum::{init, log_evidence_with, log_with, verify_evidence_with, verify_with};
use std::path::PathBuf;

fn dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sg-{name}-{}-{nanos}", std::process::id()))
}

fn remote() -> Probe {
    Probe::from_signing_key_hex(&"7e".repeat(32)).unwrap()
}

const DEC: &str = r#"{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"q","output":"a","run_id":"run-1","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":1,"cost_micro_usd":1}"#;
const EV: &str = r#"{"kind":"evidence.control_check","label":"rls_test","decision":"allow","reason":"check_passed","control":"hipaa_164_312_a1","total":25,"passed":25,"flagged":0,"detail":"x","run_id":"run-rls-1"}"#;

#[test]
fn k1_events_and_checkpoints_verify_under_the_remote_key_only() {
    let d = dir("k1");
    init(&d).unwrap();
    let signer: &dyn CheckpointSigner = &remote();
    log_with(&d, signer, DEC).unwrap();
    log_with(&d, signer, DEC.replace("run-1", "run-2").as_str()).unwrap();
    assert!(verify_with(&d, &signer.pubkey_hex())
        .unwrap()
        .starts_with("OK records=2 checkpoints=2"));
    // the file key is not the signer, so verifying under it must fail
    let file_key = Probe::from_signing_key_hex(
        // Test change (KEYS1): the node's file key for the AI ledger is decisions.key now (platinum.key is the legacy shared key).
        std::fs::read_to_string(d.join("decisions.key"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert!(verify_with(&d, &file_key.pubkey_hex()).is_err());
}

#[test]
fn k2_the_evidence_ledger_uses_the_same_signer() {
    let d = dir("k2");
    init(&d).unwrap();
    let signer: &dyn CheckpointSigner = &remote();
    log_evidence_with(&d, signer, EV).unwrap();
    assert!(verify_evidence_with(&d, &signer.pubkey_hex())
        .unwrap()
        .starts_with("OK records=1"));
}

#[test]
fn k3_a_signer_that_fails_leaves_the_ledger_unchanged() {
    struct Broken;
    impl CheckpointSigner for Broken {
        fn algorithm(&self) -> &'static str {
            "ML-DSA-65"
        }
        fn pubkey_hex(&self) -> String {
            remote().pubkey_hex()
        }
        fn try_sign_hex(&self, _m: &[u8]) -> Result<String, entropa_core::SignError> {
            Err(entropa_core::SignError::Backend("denied".into()))
        }
    }
    let d = dir("k3");
    init(&d).unwrap();
    let good: &dyn CheckpointSigner = &remote();
    log_with(&d, good, DEC).unwrap();
    assert!(log_with(&d, &Broken, DEC.replace("run-1", "run-9").as_str()).is_err());
    assert!(verify_with(&d, &good.pubkey_hex())
        .unwrap()
        .starts_with("OK records=1 checkpoints=1"));
}

#[test]
fn k4_a_failure_signing_the_checkpoint_also_leaves_the_ledger_unchanged() {
    use std::cell::Cell;
    // signs the event (first call) but fails on the checkpoint (second call)
    struct FailsSecond(Probe, Cell<u32>);
    impl CheckpointSigner for FailsSecond {
        fn algorithm(&self) -> &'static str {
            "ML-DSA-65"
        }
        fn pubkey_hex(&self) -> String {
            self.0.pubkey_hex()
        }
        fn try_sign_hex(&self, m: &[u8]) -> Result<String, entropa_core::SignError> {
            self.1.set(self.1.get() + 1);
            if self.1.get() == 2 {
                Err(entropa_core::SignError::Backend("denied".into()))
            } else {
                Ok(self.0.sign_hex(m))
            }
        }
    }
    let d = dir("k4");
    init(&d).unwrap();
    let good: &dyn CheckpointSigner = &remote();
    log_with(&d, good, DEC).unwrap();
    let flaky = FailsSecond(remote(), Cell::new(0));
    assert!(log_with(&d, &flaky, DEC.replace("run-1", "run-8").as_str()).is_err());
    assert!(verify_with(&d, &good.pubkey_hex())
        .unwrap()
        .starts_with("OK records=1 checkpoints=1"));
}
