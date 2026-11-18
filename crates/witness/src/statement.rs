//! The signed witness statement: canonical bytes, digest, verification.

use crate::decode::decode_statement;
use crate::{Statement, StatementFields, WitnessError, STATEMENT_TYPE};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Lowercase hex BLAKE3 of the raw bytes of a hex public key; empty when the key is not valid hex.
pub fn log_id_for(pubkey_hex: &str) -> String {
    match hex::decode(pubkey_hex) {
        Ok(raw) if !raw.is_empty() => hex::encode(blake3::hash(&raw).as_bytes()),
        _ => String::new(),
    }
}

fn field_map(f: &StatementFields) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        ("v", json!(1)),
        ("type", json!(STATEMENT_TYPE)),
        ("log_id", json!(f.log_id)),
        ("size", json!(f.size)),
        ("root", json!(f.root)),
        ("log_timestamp", json!(f.log_timestamp)),
        ("witness_time", json!(f.witness_time)),
        ("previous_size", json!(f.previous_size)),
        ("previous_root", json!(f.previous_root)),
        ("witness_pubkey", json!(f.witness_pubkey)),
    ])
}

/// Canonical bytes of a statement without its signature: keys sorted, no whitespace.
pub fn statement_canonical_bytes(f: &StatementFields) -> Vec<u8> {
    serde_json::to_string(&field_map(f))
        .unwrap_or_default()
        .into_bytes()
}

/// The digest that is signed: `BLAKE3("entropa-witness-statement-v1" 0x00 || u32be(len) || canonical)`.
pub fn statement_digest(canonical: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-witness-statement-v1\0");
    h.update(&(canonical.len() as u32).to_be_bytes());
    h.update(canonical);
    *h.finalize().as_bytes()
}

/// The statement as JSON text: the signed fields plus `sig`, keys sorted.
pub(crate) fn statement_json(f: &StatementFields, sig: &str) -> String {
    let mut m = field_map(f);
    m.insert("sig", json!(sig));
    serde_json::to_string(&m).unwrap_or_default()
}

/// Decode a statement and verify its signature under `witness_pubkey_hex`.
pub fn verify_statement(json: &str, witness_pubkey_hex: &str) -> Result<Statement, WitnessError> {
    let st = decode_statement(json)?;
    if st.fields.witness_pubkey != witness_pubkey_hex {
        return Err(WitnessError::BadSignature);
    }
    let digest = statement_digest(&statement_canonical_bytes(&st.fields));
    if entropa_core::verify_hex(witness_pubkey_hex, &digest, &st.sig) {
        Ok(st)
    } else {
        Err(WitnessError::BadSignature)
    }
}
