//! Strict argument validation. Error details name fields and rules, never the offending value.

use entropa_core::merkle::{ProofStep, Side};
use entropa_core::transparency_log::{Checkpoint, Receipt};
use serde_json::{Map, Value};

/// Largest JSON integer that survives a double: 2^53 - 1.
pub const MAX_SAFE_INT: u64 = (1 << 53) - 1;
/// ML-DSA-65 public key length in hex characters.
pub const PUBKEY_HEX_MAX: usize = 3904;
/// ML-DSA-65 signature length in hex characters.
pub const SIGNATURE_HEX_MAX: usize = 6618;
/// Largest record accepted by the MCP layer: 64 KiB (as hex).
pub const RECORD_HEX_MAX: usize = 2 * 64 * 1024;
/// Longest proof accepted (a tree of 2^64 leaves).
pub const PROOF_STEPS_MAX: usize = 64;

/// A rejected argument: which field, and the rule it broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgError(pub String);

fn bad<T>(field: &str, rule: &str) -> Result<T, ArgError> {
    Err(ArgError(format!("{field}: {rule}")))
}

/// The arguments must be a JSON object.
pub fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, ArgError> {
    match v.as_object() {
        Some(m) => Ok(m),
        None => bad(what, "must be a JSON object"),
    }
}

/// Reject keys outside `allowed` and require every key in `required`.
pub fn keys(
    m: &Map<String, Value>,
    what: &str,
    required: &[&str],
    allowed: &[&str],
) -> Result<(), ArgError> {
    for k in m.keys() {
        if !allowed.contains(&k.as_str()) {
            return bad(
                what,
                &format!("unexpected field (allowed: {})", allowed.join(", ")),
            );
        }
    }
    for r in required {
        if !m.contains_key(*r) {
            return bad(what, &format!("missing required field `{r}`"));
        }
    }
    Ok(())
}

/// Lowercase hex, even length, at most `max` characters, and exactly `exact` if given.
pub fn hex_field(
    v: &Value,
    field: &str,
    max: usize,
    exact: Option<usize>,
) -> Result<String, ArgError> {
    let Some(s) = v.as_str() else {
        return bad(field, "must be a string of lowercase hex");
    };
    if s.len() > max {
        return bad(field, &format!("longer than {max} characters"));
    }
    if let Some(n) = exact {
        if s.len() != n {
            return bad(field, &format!("must be exactly {n} hex characters"));
        }
    }
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return bad(field, "must be lowercase hex of even length");
    }
    Ok(s.to_string())
}

/// A non-negative integer no larger than 2^53 - 1.
pub fn uint(v: &Value, field: &str) -> Result<u64, ArgError> {
    match v.as_u64() {
        Some(n) if n <= MAX_SAFE_INT => Ok(n),
        _ => bad(field, "must be an integer from 0 to 9007199254740991"),
    }
}

/// Parse and validate a checkpoint argument.
pub fn checkpoint(v: &Value, what: &str) -> Result<Checkpoint, ArgError> {
    let m = object(v, what)?;
    let all = ["root", "size", "timestamp", "proposer_pubkey", "signature"];
    keys(m, what, &all, &all)?;
    let root = hex_field(&m["root"], &format!("{what}.root"), 64, Some(64))?;
    let size = uint(&m["size"], &format!("{what}.size"))?;
    let timestamp = uint(&m["timestamp"], &format!("{what}.timestamp"))?;
    let proposer_pubkey = hex_field(
        &m["proposer_pubkey"],
        &format!("{what}.proposer_pubkey"),
        PUBKEY_HEX_MAX,
        None,
    )?;
    let signature = hex_field(
        &m["signature"],
        &format!("{what}.signature"),
        SIGNATURE_HEX_MAX,
        None,
    )?;
    let root_bytes: [u8; 32] = hex::decode(root)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ArgError(format!("{what}.root: must be 32 bytes")))?;
    Ok(Checkpoint {
        root: root_bytes,
        size: size as usize,
        timestamp,
        proposer_pubkey,
        signature,
    })
}

/// Parse and validate a receipt argument.
pub fn receipt(v: &Value) -> Result<Receipt, ArgError> {
    let m = object(v, "receipt")?;
    let all = ["index", "record", "proof", "checkpoint"];
    keys(m, "receipt", &all, &all)?;
    let index = uint(&m["index"], "receipt.index")?;
    let record = hex::decode(hex_field(
        &m["record"],
        "receipt.record",
        RECORD_HEX_MAX,
        None,
    )?)
    .map_err(|_| ArgError("receipt.record: must be lowercase hex".into()))?;
    let Some(steps) = m["proof"].as_array() else {
        return bad("receipt.proof", "must be an array");
    };
    if steps.len() > PROOF_STEPS_MAX {
        return bad(
            "receipt.proof",
            &format!("more than {PROOF_STEPS_MAX} steps"),
        );
    }
    let mut proof = Vec::with_capacity(steps.len());
    for (i, s) in steps.iter().enumerate() {
        let what = format!("receipt.proof[{i}]");
        let sm = object(s, &what)?;
        keys(sm, &what, &["sibling", "side"], &["sibling", "side"])?;
        let sib = hex_field(&sm["sibling"], &format!("{what}.sibling"), 64, Some(64))?;
        let sibling: [u8; 32] = hex::decode(sib)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| ArgError(format!("{what}.sibling: must be 32 bytes")))?;
        let side = match sm["side"].as_str() {
            Some("Left") => Side::Left,
            Some("Right") => Side::Right,
            _ => return bad(&format!("{what}.side"), "must be \"Left\" or \"Right\""),
        };
        proof.push(ProofStep { sibling, side });
    }
    let checkpoint = checkpoint(&m["checkpoint"], "receipt.checkpoint")?;
    Ok(Receipt {
        index: index as usize,
        record,
        proof,
        checkpoint,
    })
}

/// `list_records` arguments: `limit` 1..=100 (default 20) and `since_index` >= 0 (default 0).
pub fn list_args(v: &Value) -> Result<(usize, usize), ArgError> {
    let m = object(v, "arguments")?;
    keys(m, "arguments", &[], &["limit", "since_index"])?;
    let limit = match m.get("limit") {
        None => 20,
        Some(l) => match l.as_u64() {
            Some(n) if (1..=100).contains(&n) => n,
            _ => return bad("limit", "must be an integer from 1 to 100"),
        },
    };
    let since = match m.get("since_index") {
        None => 0,
        Some(s) => uint(s, "since_index")?,
    };
    Ok((limit as usize, since as usize))
}
