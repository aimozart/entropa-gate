//! Strict decoders for requests and statements: exact field sets, lowercase hex, bounded integers.
//! Error messages name the field, never the offending value.

use crate::{
    Request, Statement, StatementFields, WitnessError, MAX_PROOF_LEN, MAX_REQUEST_BYTES,
    STATEMENT_TYPE,
};
use entropa_core::transparency_log::Checkpoint;
use serde_json::{Map, Value};

/// Largest integer a JSON number may carry (2^53 - 1), so it survives any JSON implementation.
pub(crate) const MAX_SAFE_INT: u64 = (1 << 53) - 1;
/// Longest key or signature in hex characters (ML-DSA-65: 3,904 and 6,618; some slack for other sets).
const MAX_KEY_HEX: usize = 8192;
/// Largest statement in bytes.
const MAX_STATEMENT_BYTES: usize = 32 * 1024;

fn invalid(field: &str, rule: &str) -> WitnessError {
    WitnessError::Invalid(format!("{field}: {rule}"))
}

pub(crate) fn lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex_fixed(v: &Value, field: &str, bytes: usize) -> Result<Vec<u8>, WitnessError> {
    let s = v
        .as_str()
        .ok_or_else(|| invalid(field, "must be a string"))?;
    if s.len() != bytes * 2 || !lower_hex(s) {
        return Err(invalid(field, "must be lowercase hex of the exact length"));
    }
    hex::decode(s).map_err(|_| invalid(field, "must be hex"))
}

fn hex_var(v: &Value, field: &str) -> Result<String, WitnessError> {
    let s = v
        .as_str()
        .ok_or_else(|| invalid(field, "must be a string"))?;
    if s.is_empty() || s.len() % 2 != 0 || s.len() > MAX_KEY_HEX || !lower_hex(s) {
        return Err(invalid(
            field,
            "must be non-empty lowercase hex of even, bounded length",
        ));
    }
    Ok(s.to_string())
}

fn int(v: &Value, field: &str) -> Result<u64, WitnessError> {
    match v.as_u64() {
        Some(n) if n <= MAX_SAFE_INT => Ok(n),
        _ => Err(invalid(field, "must be an integer from 0 to 2^53-1")),
    }
}

fn exact_object<'a>(
    v: &'a Value,
    field: &str,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, WitnessError> {
    let m = v
        .as_object()
        .ok_or_else(|| invalid(field, "must be an object"))?;
    if m.len() != keys.len() || !keys.iter().all(|k| m.contains_key(*k)) {
        return Err(invalid(field, "unexpected or missing field"));
    }
    Ok(m)
}

fn hash(v: &Value, field: &str) -> Result<[u8; 32], WitnessError> {
    let bytes = hex_fixed(v, field, 32)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| invalid(field, "must be 32 bytes"))
}

/// Strictly decode a cosign request body.
pub fn decode_request(body: &str) -> Result<Request, WitnessError> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(WitnessError::Limit("request body is too large".into()));
    }
    let v: Value = crate::strict_json::from_str(body)
        .map_err(|_| invalid("body", "not valid JSON or a duplicated key"))?;
    let m = exact_object(&v, "request", &["v", "log_id", "checkpoint", "consistency"])?;
    if m["v"].as_u64() != Some(1) {
        return Err(invalid("v", "unsupported version"));
    }
    let log_id = hex_fixed(&m["log_id"], "log_id", 32).map(hex::encode)?;
    let c = exact_object(
        &m["checkpoint"],
        "checkpoint",
        &["root", "size", "timestamp", "proposer_pubkey", "signature"],
    )?;
    let checkpoint = Checkpoint {
        root: hash(&c["root"], "checkpoint.root")?,
        size: usize::try_from(int(&c["size"], "checkpoint.size")?)
            .map_err(|_| invalid("checkpoint.size", "too large"))?,
        timestamp: int(&c["timestamp"], "checkpoint.timestamp")?,
        proposer_pubkey: hex_var(&c["proposer_pubkey"], "checkpoint.proposer_pubkey")?,
        signature: hex_var(&c["signature"], "checkpoint.signature")?,
    };
    let proof = m["consistency"]
        .as_array()
        .ok_or_else(|| invalid("consistency", "must be an array"))?;
    if proof.len() > MAX_PROOF_LEN {
        return Err(WitnessError::Limit("consistency proof is too long".into()));
    }
    let consistency = proof
        .iter()
        .map(|h| hash(h, "consistency[]"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Request {
        log_id,
        checkpoint,
        consistency,
    })
}

/// Strictly decode a witness statement (the signature is not checked here).
pub fn decode_statement(json: &str) -> Result<Statement, WitnessError> {
    if json.len() > MAX_STATEMENT_BYTES {
        return Err(WitnessError::Limit("statement is too large".into()));
    }
    let v: Value = crate::strict_json::from_str(json)
        .map_err(|_| invalid("statement", "not valid JSON or a duplicated key"))?;
    let m = exact_object(
        &v,
        "statement",
        &[
            "v",
            "type",
            "log_id",
            "size",
            "root",
            "log_timestamp",
            "witness_time",
            "previous_size",
            "previous_root",
            "witness_pubkey",
            "sig",
        ],
    )?;
    if m["v"].as_u64() != Some(1) {
        return Err(invalid("v", "unsupported version"));
    }
    if m["type"].as_str() != Some(STATEMENT_TYPE) {
        return Err(invalid("type", "unknown statement type"));
    }
    let fields = StatementFields {
        log_id: hex::encode(hex_fixed(&m["log_id"], "log_id", 32)?),
        size: int(&m["size"], "size")?,
        root: hex::encode(hash(&m["root"], "root")?),
        log_timestamp: int(&m["log_timestamp"], "log_timestamp")?,
        witness_time: int(&m["witness_time"], "witness_time")?,
        previous_size: int(&m["previous_size"], "previous_size")?,
        previous_root: hex::encode(hash(&m["previous_root"], "previous_root")?),
        witness_pubkey: hex_var(&m["witness_pubkey"], "witness_pubkey")?,
    };
    Ok(Statement {
        fields,
        sig: hex_var(&m["sig"], "sig")?,
    })
}
