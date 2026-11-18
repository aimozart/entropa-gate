//! Canonical encoding, signing and strict decoding of approval events.

use crate::{ActionClass, ApprovalError, Body, Event, ReasonCode, SignedEvent};
use entropa_core::transparency_log::{encode_record, TransparencyLog};
use entropa_core::CheckpointSigner;
use serde_json::{json, Map, Value};

const MAX_SAFE_INT: u64 = (1 << 53) - 1;
const MIN_VALID_FOR: u64 = 60;
const MAX_VALID_FOR: u64 = 604_800;
const MAX_TOKEN: usize = 64;
const MAX_SIG_HEX: usize = 6618;

fn invalid(field: &str, rule: &str) -> ApprovalError {
    ApprovalError::Invalid(format!("{field}: {rule}"))
}

/// First 16 hex characters of BLAKE3 over the public key bytes (empty for non-hex input).
pub fn key_id(pubkey_hex: &str) -> String {
    match hex::decode(pubkey_hex) {
        Ok(bytes) if !bytes.is_empty() => hex::encode(&blake3::hash(&bytes).as_bytes()[..8]),
        _ => String::new(),
    }
}

/// The derived request id (doc section 3).
pub(crate) fn derive_request_id(
    actor: &str,
    class: ActionClass,
    subject_hash: &str,
    ts: u64,
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-approval-request-id-v1\0");
    h.update(actor.as_bytes());
    h.update(b"\0");
    h.update(class.as_str().as_bytes());
    h.update(b"\0");
    h.update(subject_hash.as_bytes());
    h.update(b"\0");
    h.update(ts.to_string().as_bytes());
    hex::encode(h.finalize().as_bytes())
}

fn reason_name(r: ReasonCode) -> &'static str {
    match r {
        ReasonCode::NotAuthorised => "not_authorised",
        ReasonCode::WrongSubject => "wrong_subject",
        ReasonCode::TooRisky => "too_risky",
        ReasonCode::Other => "other",
    }
}

fn reason_parse(s: &str) -> Option<ReasonCode> {
    [
        ReasonCode::NotAuthorised,
        ReasonCode::WrongSubject,
        ReasonCode::TooRisky,
        ReasonCode::Other,
    ]
    .into_iter()
    .find(|r| reason_name(*r) == s)
}

fn type_name(b: &Body) -> &'static str {
    match b {
        Body::Request { .. } => "request",
        Body::Approve { .. } => "approve",
        Body::Deny { .. } => "deny",
        Body::Consume => "consume",
    }
}

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TOKEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

/// Validate every field of an event (also used before encoding).
fn validate(e: &Event) -> Result<(), ApprovalError> {
    if !lower_hex(&e.request_id, 64) {
        return Err(invalid("request_id", "must be 64 lowercase hex characters"));
    }
    if !lower_hex(&e.actor, 16) {
        return Err(invalid("actor", "must be 16 lowercase hex characters"));
    }
    if e.ts > MAX_SAFE_INT {
        return Err(invalid("ts", "out of range"));
    }
    let opt_hex = |v: &Option<String>, field: &str, len: usize| match v {
        Some(s) if !lower_hex(s, len) => {
            Err(invalid(field, "must be lowercase hex of the right length"))
        }
        _ => Ok(()),
    };
    match &e.body {
        Body::Request {
            subject_hash,
            subject_ref,
            valid_for_secs,
            ..
        } => {
            if !lower_hex(subject_hash, 64) {
                return Err(invalid(
                    "subject_hash",
                    "must be 64 lowercase hex characters",
                ));
            }
            if !token_ok(subject_ref) {
                return Err(invalid(
                    "subject_ref",
                    "must be a short token of A-Za-z0-9._:/-",
                ));
            }
            if !(MIN_VALID_FOR..=MAX_VALID_FOR).contains(valid_for_secs) {
                return Err(invalid("valid_for_secs", "must be from 60 to 604800"));
            }
        }
        Body::Approve {
            on_behalf_of,
            basis_hash,
        }
        | Body::Deny {
            on_behalf_of,
            basis_hash,
            ..
        } => {
            opt_hex(on_behalf_of, "on_behalf_of", 16)?;
            opt_hex(basis_hash, "basis_hash", 64)?;
        }
        Body::Consume => {}
    }
    Ok(())
}

fn fields(e: &Event) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("v".into(), json!(1));
    m.insert("type".into(), json!(type_name(&e.body)));
    m.insert("request_id".into(), json!(e.request_id));
    m.insert("actor".into(), json!(e.actor));
    m.insert("ts".into(), json!(e.ts));
    match &e.body {
        Body::Request {
            action_class,
            subject_hash,
            subject_ref,
            valid_for_secs,
        } => {
            m.insert("action_class".into(), json!(action_class.as_str()));
            m.insert("subject_hash".into(), json!(subject_hash));
            m.insert("subject_ref".into(), json!(subject_ref));
            m.insert("valid_for_secs".into(), json!(valid_for_secs));
        }
        Body::Approve {
            on_behalf_of,
            basis_hash,
        } => {
            if let Some(v) = on_behalf_of {
                m.insert("on_behalf_of".into(), json!(v));
            }
            if let Some(v) = basis_hash {
                m.insert("basis_hash".into(), json!(v));
            }
        }
        Body::Deny {
            reason,
            on_behalf_of,
            basis_hash,
        } => {
            m.insert("reason_code".into(), json!(reason_name(*reason)));
            if let Some(v) = on_behalf_of {
                m.insert("on_behalf_of".into(), json!(v));
            }
            if let Some(v) = basis_hash {
                m.insert("basis_hash".into(), json!(v));
            }
        }
        Body::Consume => {}
    }
    m
}

/// Canonical bytes of an event without its signature: sorted keys, no whitespace.
pub fn canonical_bytes(event: &Event) -> Vec<u8> {
    sorted_json(fields(event)).into_bytes()
}

/// Serialize with keys in sorted order. serde_json's `preserve_order` feature is switched on for
/// the whole workspace as soon as cedar-policy is built, so sorting must not rely on the default.
fn sorted_json(m: Map<String, Value>) -> String {
    let sorted: std::collections::BTreeMap<_, _> = m.into_iter().collect();
    serde_json::to_string(&sorted).unwrap_or_default()
}

/// The digest that is signed: `BLAKE3("entropa-approval-v1" 0x00 || u32be(len) || canonical bytes)`.
pub fn signing_digest(event: &Event) -> [u8; 32] {
    let bytes = canonical_bytes(event);
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-approval-v1\0");
    h.update(&(bytes.len() as u32).to_be_bytes());
    h.update(&bytes);
    *h.finalize().as_bytes()
}

/// Sign an event with any [`CheckpointSigner`] (a `Probe` in development, a KMS key in production).
pub fn sign(signer: &impl CheckpointSigner, event: &Event) -> Result<SignedEvent, ApprovalError> {
    validate(event)?;
    let sig = signer
        .try_sign_hex(&signing_digest(event))
        .map_err(|_| ApprovalError::Invalid("signing failed".into()))?;
    Ok(SignedEvent {
        event: event.clone(),
        sig,
    })
}

/// Encode a signed event as the record payload (canonical JSON plus `sig`).
pub fn encode(e: &SignedEvent) -> Result<String, ApprovalError> {
    validate(&e.event)?;
    let mut m = fields(&e.event);
    m.insert("sig".into(), json!(e.sig));
    Ok(sorted_json(m))
}

fn take_str<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str, ApprovalError> {
    m.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(k, "missing or not a string"))
}

fn take_u64(m: &Map<String, Value>, k: &str) -> Result<u64, ApprovalError> {
    m.get(k)
        .and_then(Value::as_u64)
        .filter(|n| *n <= MAX_SAFE_INT)
        .ok_or_else(|| invalid(k, "missing or not an integer in range"))
}

fn opt_str(m: &Map<String, Value>, k: &str) -> Result<Option<String>, ApprovalError> {
    match m.get(k) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(invalid(k, "not a string")),
    }
}

/// Strictly decode a record payload: exact field set per type, validated values, nothing echoed.
pub fn decode(payload: &str) -> Result<SignedEvent, ApprovalError> {
    let Ok(Value::Object(m)) = serde_json::from_str::<Value>(payload) else {
        return Err(ApprovalError::Invalid(
            "payload is not a JSON object".into(),
        ));
    };
    if m.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(invalid("v", "unsupported schema version"));
    }
    let kind = take_str(&m, "type")?.to_string();
    let (required, optional): (&[&str], &[&str]) = match kind.as_str() {
        "request" => (
            &[
                "action_class",
                "subject_hash",
                "subject_ref",
                "valid_for_secs",
            ],
            &[],
        ),
        "approve" => (&[], &["on_behalf_of", "basis_hash"]),
        "deny" => (&["reason_code"], &["on_behalf_of", "basis_hash"]),
        "consume" => (&[], &[]),
        _ => return Err(invalid("type", "unknown event type")),
    };
    let common = ["v", "type", "request_id", "actor", "ts", "sig"];
    for k in m.keys() {
        if !common.contains(&k.as_str())
            && !required.contains(&k.as_str())
            && !optional.contains(&k.as_str())
        {
            return Err(invalid("payload", "unexpected field"));
        }
    }
    for k in common.iter().chain(required.iter()) {
        if !m.contains_key(*k) {
            return Err(invalid(k, "missing"));
        }
    }
    let sig = take_str(&m, "sig")?.to_string();
    if sig.is_empty()
        || sig.len() > MAX_SIG_HEX
        || !lower_hex(&sig, sig.len())
        || sig.len() % 2 != 0
    {
        return Err(invalid("sig", "must be lowercase hex"));
    }
    let body = match kind.as_str() {
        "request" => Body::Request {
            action_class: ActionClass::parse(take_str(&m, "action_class")?)
                .ok_or_else(|| invalid("action_class", "unknown action class"))?,
            subject_hash: take_str(&m, "subject_hash")?.to_string(),
            subject_ref: take_str(&m, "subject_ref")?.to_string(),
            valid_for_secs: take_u64(&m, "valid_for_secs")?,
        },
        "approve" => Body::Approve {
            on_behalf_of: opt_str(&m, "on_behalf_of")?,
            basis_hash: opt_str(&m, "basis_hash")?,
        },
        "deny" => Body::Deny {
            reason: reason_parse(take_str(&m, "reason_code")?)
                .ok_or_else(|| invalid("reason_code", "unknown reason code"))?,
            on_behalf_of: opt_str(&m, "on_behalf_of")?,
            basis_hash: opt_str(&m, "basis_hash")?,
        },
        _ => Body::Consume,
    };
    let event = Event {
        request_id: take_str(&m, "request_id")?.to_string(),
        actor: take_str(&m, "actor")?.to_string(),
        ts: take_u64(&m, "ts")?,
        body,
    };
    validate(&event)?;
    Ok(SignedEvent { event, sig })
}

/// Append an event to the log as an Entropa record (label `approval.<type>`); returns its index.
pub fn append_event(log: &mut TransparencyLog, e: &SignedEvent) -> Result<usize, ApprovalError> {
    let payload = encode(e)?;
    let label = format!("approval.{}", type_name(&e.event.body));
    let record = encode_record(&payload, Some(&label))
        .map_err(|_| ApprovalError::Invalid("record too large".into()))?;
    Ok(log.append(&record))
}
