//! INS2 slice 2a: the anchor file (an outside holder's copy of one checkpoint: hash only, or the signed checkpoint itself). One canonical JSON line; strict decoder.
//! Format `entropa-anchor` v1, keys sorted, no spaces:
//! `{"checkpoint":null|{...},"counter":N|null,"log_id":"<64 hex>","root":"<64 hex>","size":N,"type":"anchor","v":1}`.
//! A signed checkpoint is `{"v":1,"root","size","timestamp","proposer_pubkey","signature"}` or `{"v":2,"counter","prev","root","size","timestamp","proposer_pubkey","signature"}`.
use crate::{log_id_for, strict_json};
use entropa_core::anchor::{Anchor, AnyCheckpoint, CheckpointV2};
use entropa_core::transparency_log::Checkpoint;
use serde_json::{json, Map, Value};

/// The largest anchor file the decoder reads (bytes).
pub const MAX_ANCHOR_BYTES: usize = 32 * 1024;
const MAX_HEX_KEY: usize = 8192;
/// Largest integer that survives a round trip through JSON numbers in every reader.
const MAX_SAFE_INT: u64 = (1 << 53) - 1;

/// Why an anchor file was refused. Never echoes any part of the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorFileError {
    /// Malformed, unknown, missing or out-of-range content.
    Invalid(String),
    /// Larger than [`MAX_ANCHOR_BYTES`].
    Limit(String),
    /// The anchor names another log than the one being checked (a closed refusal, not a verdict).
    WrongLog,
}

fn invalid(what: &str) -> AnchorFileError {
    AnchorFileError::Invalid(what.to_string())
}

fn checkpoint_json(c: &AnyCheckpoint) -> Value {
    match c {
        AnyCheckpoint::V1(c) => {
            json!({"v": 1, "root": hex::encode(c.root), "size": c.size, "timestamp": c.timestamp, "proposer_pubkey": c.proposer_pubkey, "signature": c.signature})
        }
        AnyCheckpoint::V2(c) => {
            json!({"v": 2, "counter": c.counter, "prev": hex::encode(c.prev), "root": hex::encode(c.root), "size": c.size, "timestamp": c.timestamp, "proposer_pubkey": c.proposer_pubkey, "signature": c.signature})
        }
    }
}

/// The canonical one-line text of an anchor for the log whose id is `log_id`.
pub fn encode_anchor(a: &Anchor, log_id: &str) -> String {
    let v = json!({
        "v": 1, "type": "anchor", "log_id": log_id, "size": a.size, "root": hex::encode(a.root),
        "counter": a.counter, "checkpoint": a.signed.as_ref().map(checkpoint_json),
    });
    canonical(&v)
}

/// JSON text with the keys of every object sorted, whatever the `serde_json` feature set of the build (a workspace build can turn on `preserve_order`, which keeps insertion order).
fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut pairs: Vec<(&String, &Value)> = m.iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(b.0));
            let body: Vec<String> = pairs
                .iter()
                .map(|(k, x)| format!("{}:{}", Value::String((*k).clone()), canonical(x)))
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

fn exact<'a>(v: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, AnchorFileError> {
    let m = v.as_object().ok_or_else(|| invalid("expected an object"))?;
    if m.len() != keys.len() || !keys.iter().all(|k| m.contains_key(*k)) {
        return Err(invalid("unexpected or missing field"));
    }
    Ok(m)
}
fn lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash(v: &Value) -> Result<[u8; 32], AnchorFileError> {
    let s = v.as_str().ok_or_else(|| invalid("expected a hash"))?;
    if s.len() != 64 || !lower_hex(s) {
        return Err(invalid("a hash is 64 lower-case hex digits"));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| invalid("a hash is 64 lower-case hex digits"))?;
    Ok(out)
}
fn key_hex(v: &Value) -> Result<String, AnchorFileError> {
    let s = v.as_str().ok_or_else(|| invalid("expected hex"))?;
    if s.is_empty() || s.len() > MAX_HEX_KEY || s.len() % 2 != 0 || !lower_hex(s) {
        return Err(invalid("expected lower-case hex of bounded length"));
    }
    Ok(s.to_string())
}
fn int(v: &Value) -> Result<u64, AnchorFileError> {
    match v.as_u64() {
        Some(n) if n <= MAX_SAFE_INT => Ok(n),
        _ => Err(invalid("expected a whole number in range")),
    }
}

fn decode_checkpoint(v: &Value) -> Result<AnyCheckpoint, AnchorFileError> {
    let version = v.get("v").and_then(Value::as_u64);
    match version {
        Some(1) => {
            let m = exact(
                v,
                &[
                    "v",
                    "root",
                    "size",
                    "timestamp",
                    "proposer_pubkey",
                    "signature",
                ],
            )?;
            Ok(AnyCheckpoint::V1(Checkpoint {
                root: hash(&m["root"])?,
                size: usize::try_from(int(&m["size"])?).map_err(|_| invalid("size"))?,
                timestamp: int(&m["timestamp"])?,
                proposer_pubkey: key_hex(&m["proposer_pubkey"])?,
                signature: key_hex(&m["signature"])?,
            }))
        }
        Some(2) => {
            let m = exact(
                v,
                &[
                    "v",
                    "counter",
                    "prev",
                    "root",
                    "size",
                    "timestamp",
                    "proposer_pubkey",
                    "signature",
                ],
            )?;
            let counter = int(&m["counter"])?;
            if counter == 0 {
                return Err(invalid("a counter starts at 1"));
            }
            Ok(AnyCheckpoint::V2(CheckpointV2 {
                counter,
                prev: hash(&m["prev"])?,
                root: hash(&m["root"])?,
                size: usize::try_from(int(&m["size"])?).map_err(|_| invalid("size"))?,
                timestamp: int(&m["timestamp"])?,
                proposer_pubkey: key_hex(&m["proposer_pubkey"])?,
                signature: key_hex(&m["signature"])?,
            }))
        }
        _ => Err(invalid("unknown checkpoint version")),
    }
}

/// Strictly decode an anchor file: the anchor and the log id it names.
pub fn decode_anchor(text: &str) -> Result<(Anchor, String), AnchorFileError> {
    if text.len() > MAX_ANCHOR_BYTES {
        return Err(AnchorFileError::Limit(
            "anchor file is larger than 32 KiB".into(),
        ));
    }
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.contains('\n') || body.contains('\r') {
        return Err(invalid("the anchor file is one line"));
    }
    let v =
        strict_json::from_str(body).map_err(|_| invalid("not valid JSON or a duplicated key"))?;
    let m = exact(
        &v,
        &[
            "v",
            "type",
            "log_id",
            "size",
            "root",
            "counter",
            "checkpoint",
        ],
    )?;
    if m["v"].as_u64() != Some(1) || m["type"].as_str() != Some("anchor") {
        return Err(invalid("not an anchor file of version 1"));
    }
    let log_id = hex::encode(hash(&m["log_id"])?);
    let size = usize::try_from(int(&m["size"])?).map_err(|_| invalid("size"))?;
    let root = hash(&m["root"])?;
    let counter = match &m["counter"] {
        Value::Null => None,
        c => match int(c)? {
            0 => return Err(invalid("a counter starts at 1")),
            n => Some(n),
        },
    };
    let signed = match &m["checkpoint"] {
        Value::Null => None,
        c => Some(decode_checkpoint(c)?),
    };
    if let Some(cp) = &signed {
        let (cp_size, cp_root, cp_counter, cp_key) = match cp {
            AnyCheckpoint::V1(c) => (c.size, c.root, None, c.proposer_pubkey.as_str()),
            AnyCheckpoint::V2(c) => (c.size, c.root, Some(c.counter), c.proposer_pubkey.as_str()),
        };
        if cp_size != size || cp_root != root || cp_counter != counter {
            return Err(invalid("the checkpoint disagrees with the anchor fields"));
        }
        if log_id_for(cp_key) != log_id {
            return Err(invalid("the checkpoint is signed by another log's key"));
        }
    }
    Ok((
        Anchor {
            size,
            root,
            counter,
            signed,
        },
        log_id,
    ))
}

/// Decode an anchor and refuse it unless it names the log of `expected_pubkey_hex`.
pub fn decode_anchor_for(text: &str, expected_pubkey_hex: &str) -> Result<Anchor, AnchorFileError> {
    let (anchor, log_id) = decode_anchor(text)?;
    let want = log_id_for(expected_pubkey_hex);
    if want.is_empty() || want != log_id {
        return Err(AnchorFileError::WrongLog);
    }
    Ok(anchor)
}
