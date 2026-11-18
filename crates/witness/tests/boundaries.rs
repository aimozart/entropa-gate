//! S5c: boundary tests added after the first mutation run (limits at the edge, error text, key-id input).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_witness::*;
use serde_json::{json, Value};

fn base() -> Value {
    let log = log_with(5);
    request_value(&log.log_id(), &log.checkpoint(5, TS), &log.proof(3, 5))
}

fn padded(json: &str, total: usize) -> String {
    assert!(json.len() <= total);
    format!("{json}{}", " ".repeat(total - json.len()))
}

#[test]
fn b1_the_body_limit_is_exact() {
    let s = base().to_string();
    assert!(decode_request(&padded(&s, MAX_REQUEST_BYTES)).is_ok());
    assert!(matches!(
        decode_request(&padded(&s, MAX_REQUEST_BYTES + 1)),
        Err(WitnessError::Limit(_))
    ));
}

#[test]
fn b2_key_and_signature_hex_length_limits_are_exact() {
    for field in ["proposer_pubkey", "signature"] {
        let mut v = base();
        v["checkpoint"][field] = json!("ab".repeat(4096));
        assert!(
            decode_request(&v.to_string()).is_ok(),
            "{field} at 8192 hex characters"
        );
        v["checkpoint"][field] = json!("ab".repeat(4097));
        assert!(
            matches!(
                decode_request(&v.to_string()),
                Err(WitnessError::Invalid(_))
            ),
            "{field} at 8194 hex characters"
        );
    }
}

#[test]
fn b3_the_statement_size_limit_is_exact() {
    let log = log_with(4);
    let (w, _) = witness(&log, true);
    let json = w
        .cosign(&body(&log.log_id(), &log.checkpoint(4, TS), &[]), NOW)
        .unwrap();
    let limit = 32 * 1024;
    assert!(decode_statement(&padded(&json, limit)).is_ok());
    assert!(matches!(
        decode_statement(&padded(&json, limit + 1)),
        Err(WitnessError::Limit(_))
    ));
}

#[test]
fn b4_log_id_for_rejects_empty_and_non_hex_keys() {
    assert_eq!(log_id_for(""), "");
    assert_eq!(log_id_for("zz"), "");
    assert_eq!(log_id_for("abc"), "");
    assert_eq!(log_id_for("00").len(), 64);
}

#[test]
fn b5_every_error_has_its_own_readable_message() {
    let all = [
        WitnessError::Invalid("x".into()),
        WitnessError::Limit("x".into()),
        WitnessError::UnknownLog,
        WitnessError::BadSignature,
        WitnessError::FirstNotAllowed,
        WitnessError::Rollback,
        WitnessError::Equivocation,
        WitnessError::BadConsistency,
        WitnessError::StoreConflict,
        WitnessError::Store("x".into()),
        WitnessError::Sign("x".into()),
    ];
    let texts: Vec<String> = all.iter().map(|e| e.to_string()).collect();
    assert!(texts.iter().all(|t| t.len() > 8), "{texts:?}");
    let mut unique = texts.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), texts.len(), "messages must differ");
}
