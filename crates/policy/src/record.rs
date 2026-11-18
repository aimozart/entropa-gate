//! Signed, data-minimal decision records (doc section 7).

use crate::{Action, Decision, DecisionRecord, Outcome, PolicyError, Reason, Request};
use entropa_approvals::BlockReason;
use entropa_core::transparency_log::{encode_record, TransparencyLog};
use entropa_core::CheckpointSigner;
use serde_json::{json, Map, Value};

const MAX_LIST: usize = 64;
const MAX_SAFE_INT: u64 = (1 << 53) - 1;
const STATES: [&str; 7] = [
    "none",
    "pending",
    "denied",
    "expired",
    "used",
    "approved",
    "attestation_only",
];
const REASONS: [&str; 12] = [
    "allowed",
    "cedar_deny",
    "policy_error",
    "attestation_not_accepted",
    "invalid_request",
    "gate_no_request",
    "gate_pending",
    "gate_denied",
    "gate_expired",
    "gate_already_used",
    "gate_subject_mismatch",
    "gate_attestation_not_accepted",
];

fn reason_name(r: Reason) -> &'static str {
    match r {
        Reason::NotImplemented => "invalid_request",
        Reason::Allowed => "allowed",
        Reason::CedarDeny => "cedar_deny",
        Reason::PolicyError => "policy_error",
        Reason::AttestationNotAccepted => "attestation_not_accepted",
        Reason::InvalidRequest => "invalid_request",
        Reason::GateBlocked(b) => match b {
            BlockReason::NoRequest => "gate_no_request",
            BlockReason::Pending => "gate_pending",
            BlockReason::Denied => "gate_denied",
            BlockReason::Expired => "gate_expired",
            BlockReason::AlreadyUsed => "gate_already_used",
            BlockReason::SubjectMismatch => "gate_subject_mismatch",
            BlockReason::AttestationNotAccepted => "gate_attestation_not_accepted",
        },
    }
}

fn outcome_name(o: Outcome) -> &'static str {
    match o {
        Outcome::Allow => "allow",
        Outcome::Deny => "deny",
    }
}

fn invalid(field: &str, rule: &str) -> PolicyError {
    PolicyError::Invalid(format!("{field}: {rule}"))
}

fn fields(
    req: &Request,
    d: &Decision,
    policy_set_hash: &str,
    ts: u64,
    actor: &str,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("v".into(), json!(1));
    m.insert("type".into(), json!("policy.decision"));
    m.insert("actor".into(), json!(actor));
    m.insert("ts".into(), json!(ts));
    m.insert("principal".into(), json!(req.principal));
    m.insert("action".into(), json!(req.action.as_str()));
    m.insert("subject_hash".into(), json!(req.subject_hash));
    m.insert("cedar".into(), json!(d.cedar.map_or("none", outcome_name)));
    m.insert("determining".into(), json!(d.determining));
    m.insert("errors".into(), json!(d.error_policies));
    m.insert("approval_state".into(), json!(d.approval_state));
    m.insert("approval_attested".into(), json!(d.approval_attested));
    m.insert("final".into(), json!(outcome_name(d.outcome)));
    m.insert("reason".into(), json!(reason_name(d.reason)));
    m.insert("enforced".into(), json!(d.enforced));
    m.insert("policy_set_hash".into(), json!(policy_set_hash));
    m
}

/// Canonical bytes of the decision record without its signature: sorted keys, no whitespace.
pub fn record_canonical_bytes(
    req: &Request,
    d: &Decision,
    policy_set_hash: &str,
    ts: u64,
    actor: &str,
) -> Vec<u8> {
    sorted_json(fields(req, d, policy_set_hash, ts, actor)).into_bytes()
}

/// The digest that is signed: `BLAKE3("entropa-policy-decision-v1" 0x00 || u32be(len) || canonical)`.
pub fn record_digest(canonical: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-policy-decision-v1\0");
    h.update(&(canonical.len() as u32).to_be_bytes());
    h.update(canonical);
    *h.finalize().as_bytes()
}

/// Build and sign a decision record.
pub fn sign_record(
    signer: &impl CheckpointSigner,
    actor: &str,
    req: &Request,
    d: &Decision,
    policy_set_hash: &str,
    ts: u64,
) -> Result<DecisionRecord, PolicyError> {
    let canon = record_canonical_bytes(req, d, policy_set_hash, ts, actor);
    let sig = signer
        .try_sign_hex(&record_digest(&canon))
        .map_err(|_| PolicyError::Invalid("signing failed".into()))?;
    let mut m = fields(req, d, policy_set_hash, ts, actor);
    m.insert("sig".into(), json!(sig));
    Ok(DecisionRecord {
        payload: sorted_json(m),
    })
}

/// Serialize with keys in sorted order whatever serde_json's map ordering feature is.
fn sorted_json(m: Map<String, Value>) -> String {
    let sorted: std::collections::BTreeMap<_, _> = m.into_iter().collect();
    serde_json::to_string(&sorted).unwrap_or_default()
}

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

fn str_of<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str, PolicyError> {
    m.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(k, "missing or not a string"))
}

fn list_of(m: &Map<String, Value>, k: &str) -> Result<(), PolicyError> {
    let a = m
        .get(k)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(k, "missing or not an array"))?;
    if a.len() > MAX_LIST || !a.iter().all(|v| v.as_str().is_some_and(token_ok)) {
        return Err(invalid(k, "must be a short list of tokens"));
    }
    Ok(())
}

/// Strictly decode a record payload: exact field set, validated vocabulary, nothing echoed.
pub fn decode_record(payload: &str) -> Result<DecisionRecord, PolicyError> {
    let Ok(Value::Object(m)) = serde_json::from_str::<Value>(payload) else {
        return Err(PolicyError::Invalid("payload is not a JSON object".into()));
    };
    const KEYS: [&str; 17] = [
        "v",
        "type",
        "actor",
        "ts",
        "principal",
        "action",
        "subject_hash",
        "cedar",
        "determining",
        "errors",
        "approval_state",
        "approval_attested",
        "final",
        "reason",
        "enforced",
        "policy_set_hash",
        "sig",
    ];
    if m.len() != KEYS.len() || !KEYS.iter().all(|k| m.contains_key(*k)) {
        return Err(invalid("payload", "unexpected or missing field"));
    }
    if m["v"].as_u64() != Some(1) {
        return Err(invalid("v", "unsupported schema version"));
    }
    if str_of(&m, "type")? != "policy.decision" {
        return Err(invalid("type", "unknown record type"));
    }
    if !lower_hex(str_of(&m, "actor")?, 16) || !lower_hex(str_of(&m, "principal")?, 16) {
        return Err(invalid(
            "actor/principal",
            "must be 16 lowercase hex characters",
        ));
    }
    if !lower_hex(str_of(&m, "subject_hash")?, 64) || !lower_hex(str_of(&m, "policy_set_hash")?, 64)
    {
        return Err(invalid("hash", "must be 64 lowercase hex characters"));
    }
    if !m["ts"].as_u64().is_some_and(|t| t <= MAX_SAFE_INT) {
        return Err(invalid("ts", "must be an integer in range"));
    }
    if Action::parse(str_of(&m, "action")?).is_none() {
        return Err(invalid("action", "unknown action"));
    }
    if !["allow", "deny", "none"].contains(&str_of(&m, "cedar")?)
        || !["allow", "deny"].contains(&str_of(&m, "final")?)
    {
        return Err(invalid("decision", "unknown value"));
    }
    if !STATES.contains(&str_of(&m, "approval_state")?) || !REASONS.contains(&str_of(&m, "reason")?)
    {
        return Err(invalid("vocabulary", "unknown value"));
    }
    if m["approval_attested"].as_bool().is_none() || m["enforced"].as_bool().is_none() {
        return Err(invalid("flags", "must be booleans"));
    }
    list_of(&m, "determining")?;
    list_of(&m, "errors")?;
    let sig = str_of(&m, "sig")?;
    if sig.is_empty() || sig.len() > 6618 || sig.len() % 2 != 0 || !lower_hex(sig, sig.len()) {
        return Err(invalid("sig", "must be lowercase hex"));
    }
    Ok(DecisionRecord {
        payload: payload.to_string(),
    })
}

/// Append a decision record to the log (label `policy.decision`); returns its index.
pub fn append_record(log: &mut TransparencyLog, r: &DecisionRecord) -> Result<usize, PolicyError> {
    let record = encode_record(&r.payload, Some("policy.decision"))
        .map_err(|_| PolicyError::Invalid("record too large".into()))?;
    Ok(log.append(&record))
}
