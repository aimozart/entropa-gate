//! The event: fields, canonical bytes, signature, strict decoder.

use crate::vocab::{
    ControlCode, Decision, Handle, Kind, LabelCode, Provider, ReasonCode, RoleCode, Tenant,
};
use crate::{LedgerError, EVENT_TYPE, MAX_EVENT_BYTES};
use entropa_core::CheckpointSigner;
use serde_json::{json, Map, Value};

/// Largest integer a JSON number may carry (2^53 - 1).
pub(crate) const MAX_SAFE_INT: u64 = (1 << 53) - 1;

/// Model call metadata: counts and ids only, never prompts or answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMeta {
    /// Provider.
    pub provider: Provider,
    /// Model id token (letters, digits and `. _ : / -`, at most 64).
    pub model_id: String,
    /// Input tokens.
    pub input_tokens: u64,
    /// Output tokens.
    pub output_tokens: u64,
    /// Cost in millionths of a dollar.
    pub cost_micro_usd: u64,
}

/// Evidence metadata: the control supported and three counts whose meaning depends on the kind
/// (run: input, valid, quarantined; check: tests, passed, failed; access: requested, returned, masked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceMeta {
    /// The control this evidence supports.
    pub control: ControlCode,
    /// Total items examined.
    pub total: u64,
    /// Items that passed or were returned.
    pub passed: u64,
    /// Items flagged, quarantined or masked.
    pub flagged: u64,
}

/// The signed fields of an event (everything except the signature). `synthetic` is always true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFields {
    /// Kind.
    pub kind: Kind,
    /// Tenant.
    pub tenant: Tenant,
    /// The signer's key id (16 lowercase hex); for a directory event, the registered actor's key id.
    pub key_id: String,
    /// The actor's public handle.
    pub handle: Handle,
    /// Unix seconds.
    pub ts: u64,
    /// 64 lowercase hex: hash of the subject.
    pub subject_hash: String,
    /// Label code.
    pub label: LabelCode,
    /// Decision code.
    pub decision: Decision,
    /// Reason code.
    pub reason: ReasonCode,
    /// 64 hex: hash of a related approval request, if any.
    pub approval_ref: Option<String>,
    /// Model metadata, for agent invocations.
    pub agent: Option<AgentMeta>,
    /// Role, for directory events.
    pub role: Option<RoleCode>,
    /// Who attests for this actor, for directory events.
    pub attested_by: Option<Handle>,
    /// 16 hex fingerprint of the public key, for directory events.
    pub pubkey_fingerprint: Option<String>,
    /// Evidence metadata, for the evidence kinds only.
    pub evidence: Option<EvidenceMeta>,
}

/// A signed event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The signed fields.
    pub fields: EventFields,
    /// ML-DSA signature, lowercase hex.
    pub sig: String,
}

fn invalid(field: &str, rule: &str) -> LedgerError {
    LedgerError::Invalid(format!("{field}: {rule}"))
}

/// JSON text with object keys sorted at every level and no whitespace.
pub(crate) fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(&m[k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical_json).collect::<Vec<_>>().join(",")
        ),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn fields_value(f: &EventFields) -> Value {
    let mut v = json!({
        "v": 1, "type": EVENT_TYPE, "synthetic": true,
        "kind": f.kind.as_str(), "tenant": f.tenant.as_str(), "key_id": f.key_id, "handle": f.handle.as_str(),
        "ts": f.ts, "subject_hash": f.subject_hash, "label": f.label.as_str(), "decision": f.decision.as_str(),
        "reason": f.reason.as_str(), "approval_ref": f.approval_ref,
        "agent": f.agent.as_ref().map(|a| json!({"provider": a.provider.as_str(), "model_id": a.model_id,
            "input_tokens": a.input_tokens, "output_tokens": a.output_tokens, "cost_micro_usd": a.cost_micro_usd})),
        "role": f.role.map(RoleCode::as_str), "attested_by": f.attested_by.map(Handle::as_str),
        "pubkey_fingerprint": f.pubkey_fingerprint,
    });
    // Only evidence events carry the key, so every earlier event keeps its exact canonical bytes.
    if let (Some(e), Value::Object(m)) = (&f.evidence, &mut v) {
        m.insert(
            "evidence".into(),
            json!({"control": e.control.as_str(), "total": e.total, "passed": e.passed, "flagged": e.flagged}),
        );
    }
    v
}

/// Canonical bytes of an event without its signature: keys sorted, no whitespace.
pub fn event_canonical_bytes(f: &EventFields) -> Vec<u8> {
    canonical_json(&fields_value(f)).into_bytes()
}

/// The signed digest: `BLAKE3("entropa-explorer-event-v1" 0x00 || u32be(len) || canonical)`.
pub fn event_digest(canonical: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-explorer-event-v1\0");
    h.update(&(canonical.len() as u32).to_be_bytes());
    h.update(canonical);
    *h.finalize().as_bytes()
}

/// Sign an event.
pub fn sign_event(signer: &impl CheckpointSigner, f: &EventFields) -> Result<Event, LedgerError> {
    let digest = event_digest(&event_canonical_bytes(f));
    let sig = signer
        .try_sign_hex(&digest)
        .map_err(|e| LedgerError::Sign(e.to_string()))?;
    Ok(Event {
        fields: f.clone(),
        sig,
    })
}

/// The record payload (JSON text) of a signed event.
pub fn encode_event(e: &Event) -> Result<String, LedgerError> {
    let mut v = fields_value(&e.fields);
    if let Value::Object(m) = &mut v {
        m.insert("sig".into(), json!(e.sig));
    }
    let text = canonical_json(&v);
    if text.len() > MAX_EVENT_BYTES {
        return Err(LedgerError::Limit("event is too large".into()));
    }
    Ok(text)
}

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex_str(v: &Value, field: &str, len: usize) -> Result<String, LedgerError> {
    match v.as_str() {
        Some(s) if lower_hex(s, len) => Ok(s.to_string()),
        _ => Err(invalid(field, "must be lowercase hex of the exact length")),
    }
}

fn opt_hex(v: &Value, field: &str, len: usize) -> Result<Option<String>, LedgerError> {
    if v.is_null() {
        Ok(None)
    } else {
        hex_str(v, field, len).map(Some)
    }
}

fn int(v: &Value, field: &str) -> Result<u64, LedgerError> {
    match v.as_u64() {
        Some(n) if n <= MAX_SAFE_INT => Ok(n),
        _ => Err(invalid(field, "must be an integer from 0 to 2^53-1")),
    }
}

fn token(v: &Value, field: &str) -> Result<String, LedgerError> {
    match v.as_str() {
        Some(s)
            if !s.is_empty()
                && s.len() <= 64
                && s.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-')
                }) =>
        {
            Ok(s.to_string())
        }
        _ => Err(invalid(field, "must be a short token")),
    }
}

fn exact<'a>(
    v: &'a Value,
    field: &str,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, LedgerError> {
    let m = v
        .as_object()
        .ok_or_else(|| invalid(field, "must be an object"))?;
    if m.len() != keys.len() || !keys.iter().all(|k| m.contains_key(*k)) {
        return Err(invalid(field, "unexpected or missing field"));
    }
    Ok(m)
}

fn closed<T>(v: &Value, field: &str, parse: fn(&str) -> Option<T>) -> Result<T, LedgerError> {
    v.as_str()
        .and_then(parse)
        .ok_or_else(|| invalid(field, "not in the closed list"))
}

fn closed_opt<T>(
    v: &Value,
    field: &str,
    parse: fn(&str) -> Option<T>,
) -> Result<Option<T>, LedgerError> {
    if v.is_null() {
        Ok(None)
    } else {
        closed(v, field, parse).map(Some)
    }
}

/// Strictly decode an event payload.
pub fn decode_event(payload: &str) -> Result<Event, LedgerError> {
    if payload.len() > MAX_EVENT_BYTES {
        return Err(LedgerError::Limit("event is too large".into()));
    }
    let v: Value = entropa_witness::strict_json::from_str(payload)
        .map_err(|_| invalid("payload", "not valid JSON or a duplicated key"))?;
    let has_evidence = v.get("evidence").is_some();
    let mut keys = vec![
        "v",
        "type",
        "synthetic",
        "kind",
        "tenant",
        "key_id",
        "handle",
        "ts",
        "subject_hash",
        "label",
        "decision",
        "reason",
        "approval_ref",
        "agent",
        "role",
        "attested_by",
        "pubkey_fingerprint",
        "sig",
    ];
    if has_evidence {
        keys.push("evidence");
    }
    let m = exact(&v, "event", &keys)?;
    if m["v"].as_u64() != Some(1) {
        return Err(invalid("v", "unsupported version"));
    }
    if m["type"].as_str() != Some(EVENT_TYPE) {
        return Err(invalid("type", "unknown event type"));
    }
    if m["synthetic"].as_bool() != Some(true) {
        return Err(invalid("synthetic", "must be true"));
    }
    let agent = if m["agent"].is_null() {
        None
    } else {
        let a = exact(
            &m["agent"],
            "agent",
            &[
                "provider",
                "model_id",
                "input_tokens",
                "output_tokens",
                "cost_micro_usd",
            ],
        )?;
        Some(AgentMeta {
            provider: closed(&a["provider"], "agent.provider", Provider::parse)?,
            model_id: token(&a["model_id"], "agent.model_id")?,
            input_tokens: int(&a["input_tokens"], "agent.input_tokens")?,
            output_tokens: int(&a["output_tokens"], "agent.output_tokens")?,
            cost_micro_usd: int(&a["cost_micro_usd"], "agent.cost_micro_usd")?,
        })
    };
    let evidence = if has_evidence {
        let e = exact(
            &m["evidence"],
            "evidence",
            &["control", "total", "passed", "flagged"],
        )?;
        Some(EvidenceMeta {
            control: closed(&e["control"], "evidence.control", ControlCode::parse)?,
            total: int(&e["total"], "evidence.total")?,
            passed: int(&e["passed"], "evidence.passed")?,
            flagged: int(&e["flagged"], "evidence.flagged")?,
        })
    } else {
        None
    };
    let fields = EventFields {
        kind: closed(&m["kind"], "kind", Kind::parse)?,
        tenant: closed(&m["tenant"], "tenant", Tenant::parse)?,
        key_id: hex_str(&m["key_id"], "key_id", 16)?,
        handle: closed(&m["handle"], "handle", Handle::parse)?,
        ts: int(&m["ts"], "ts")?,
        subject_hash: hex_str(&m["subject_hash"], "subject_hash", 64)?,
        label: closed(&m["label"], "label", LabelCode::parse)?,
        decision: closed(&m["decision"], "decision", Decision::parse)?,
        reason: closed(&m["reason"], "reason", ReasonCode::parse)?,
        approval_ref: opt_hex(&m["approval_ref"], "approval_ref", 64)?,
        agent,
        role: closed_opt(&m["role"], "role", RoleCode::parse)?,
        attested_by: closed_opt(&m["attested_by"], "attested_by", Handle::parse)?,
        pubkey_fingerprint: opt_hex(&m["pubkey_fingerprint"], "pubkey_fingerprint", 16)?,
        evidence,
    };
    if fields.kind.is_evidence() != fields.evidence.is_some() {
        return Err(invalid(
            "evidence",
            "evidence belongs to evidence events only",
        ));
    }
    let directory = fields.kind == Kind::DirectoryActor;
    let extras_ok = if directory {
        fields.role.is_some() && fields.pubkey_fingerprint.is_some() && fields.agent.is_none()
    } else {
        fields.role.is_none() && fields.attested_by.is_none() && fields.pubkey_fingerprint.is_none()
    };
    if !extras_ok {
        return Err(invalid(
            "kind",
            "directory fields belong to directory events only",
        ));
    }
    let sig = match m["sig"].as_str() {
        Some(s) if s.len() >= 2 && s.len() <= 8192 && s.len() % 2 == 0 && lower_hex(s, s.len()) => {
            s.to_string()
        }
        _ => return Err(invalid("sig", "must be lowercase hex")),
    };
    Ok(Event { fields, sig })
}

/// Decode an event and verify its signature under `pubkey_hex`.
pub fn verify_event(payload: &str, pubkey_hex: &str) -> Result<Event, LedgerError> {
    let ev = decode_event(payload)?;
    let digest = event_digest(&event_canonical_bytes(&ev.fields));
    if entropa_core::verify_hex(pubkey_hex, &digest, &ev.sig) {
        Ok(ev)
    } else {
        Err(LedgerError::Verify(
            "event signature does not verify".into(),
        ))
    }
}
