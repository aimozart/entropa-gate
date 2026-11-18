//! NODECORE (a stage record (not published)): the ONE network-free implementation of "validate a request, sign it, append it with a signed checkpoint" and "re-read a ledger and check
//! every signature". The request parser is strict: a duplicated key is refused in every schema (decision D1, the reviewer 2026-11-16). No network, no KMS, no clock except the default `ts`.
use entropa_core::transparency_log::{decode_record, encode_record, TransparencyLog};
use entropa_core::{CheckpointSigner, SignError};
use entropa_ledger::{
    council_fields, encode_event, evidence_fields, platinum_fields, sign_event, verify_event,
    AgentMeta, ControlCode, CouncilStep, Decision, EventFields, EvidenceRecord, FileStore, Handle,
    Kind, LabelCode, LedgerStore, PlatinumDecision, Provider, ReasonCode,
};
use serde_json::Value;
use std::path::Path;

/// Why a node operation failed. `Display` is the bare message (no prefix): the callers add their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    /// The request is not acceptable (closed list, shape, size).
    Invalid(String),
    /// A file or signer failed.
    Io(String),
    /// A ledger failed verification.
    Verify(String),
    /// The store itself refused, at the named stage; the text is the store's own.
    Store(StoreStage, String),
}

/// Where in an append the store refused (the gate words each stage differently).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreStage {
    /// Opening the ledger directory.
    Open,
    /// Writing the record line.
    Append,
    /// Writing the checkpoint line.
    Checkpoint,
}
impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Invalid(m)
            | NodeError::Io(m)
            | NodeError::Verify(m)
            | NodeError::Store(_, m) => f.write_str(m),
        }
    }
}
impl std::error::Error for NodeError {}

/// What an append returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Position in the ledger.
    pub index: u64,
    /// Hash of the subject (never the text).
    pub subject_hash: String,
    /// Ledger size after the append.
    pub size: u64,
    /// Merkle root after the append (hex).
    pub root: String,
}

/// A borrowed signer behind a trait object, usable where a sized signer is expected.
struct Dyn<'a>(&'a dyn CheckpointSigner);
impl CheckpointSigner for Dyn<'_> {
    fn algorithm(&self) -> &'static str {
        self.0.algorithm()
    }
    fn pubkey_hex(&self) -> String {
        self.0.pubkey_hex()
    }
    fn try_sign_hex(&self, msg: &[u8]) -> Result<String, SignError> {
        self.0.try_sign_hex(msg)
    }
}

fn invalid<T>(m: impl Into<String>) -> Result<T, NodeError> {
    Err(NodeError::Invalid(m.into()))
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, NodeError> {
    v[k].as_str()
        .ok_or_else(|| NodeError::Invalid(format!("{k}: required text")))
}
fn num(v: &Value, k: &str) -> Result<u64, NodeError> {
    v[k].as_u64()
        .ok_or_else(|| NodeError::Invalid(format!("{k}: required whole number")))
}
fn closed<T>(x: Option<T>, k: &str) -> Result<T, NodeError> {
    x.ok_or_else(|| NodeError::Invalid(format!("{k}: not in the closed list")))
}

/// Parse a request strictly (duplicated keys refused), check it is an object whose keys are all in `allowed` (or `ts`).
fn parse(request: &str, allowed: &[&str]) -> Result<Value, NodeError> {
    let v = entropa_witness::strict_json::from_str(request)
        .map_err(|_| NodeError::Invalid("request is not JSON (or has a duplicated key)".into()))?;
    let obj = v
        .as_object()
        .ok_or_else(|| NodeError::Invalid("request must be an object".into()))?;
    if let Some(k) = obj
        .keys()
        .find(|k| !allowed.contains(&k.as_str()) && k.as_str() != "ts")
    {
        return invalid(format!(
            "unknown field: {}",
            k.chars().take(32).collect::<String>()
        ));
    }
    Ok(v)
}
fn model(v: &Value) -> Result<AgentMeta, NodeError> {
    Ok(AgentMeta {
        provider: closed(Provider::parse(text(v, "provider")?), "provider")?,
        model_id: text(v, "model_id")?.to_string(),
        input_tokens: num(v, "input_tokens")?,
        output_tokens: num(v, "output_tokens")?,
        cost_micro_usd: num(v, "cost_micro_usd")?,
    })
}
fn ts(v: &Value) -> u64 {
    v.get("ts").and_then(Value::as_u64).unwrap_or_else(now)
}

const DECISION_FIELDS: [&str; 11] = [
    "label",
    "decision",
    "reason",
    "input",
    "output",
    "run_id",
    "provider",
    "model_id",
    "input_tokens",
    "output_tokens",
    "cost_micro_usd",
];
const EVIDENCE_FIELDS: [&str; 10] = [
    "kind", "label", "decision", "reason", "control", "total", "passed", "flagged", "detail",
    "run_id",
];
const COUNCIL_FIELDS: [&str; 11] = [
    "label",
    "actor",
    "decision",
    "reason",
    "subject",
    "session_id",
    "provider",
    "model_id",
    "input_tokens",
    "output_tokens",
    "cost_micro_usd",
];

/// Validate one AI-decision request (strict JSON, duplicate keys refused) into event fields; `ts` defaults to now.
pub fn decision_fields(request: &str, pubkey_hex: &str) -> Result<EventFields, NodeError> {
    let v = parse(request, &DECISION_FIELDS)?;
    let d = PlatinumDecision {
        label: closed(LabelCode::parse(text(&v, "label")?), "label")?,
        decision: closed(Decision::parse(text(&v, "decision")?), "decision")?,
        reason: closed(ReasonCode::parse(text(&v, "reason")?), "reason")?,
        input: text(&v, "input")?,
        output: text(&v, "output")?,
        run_id: text(&v, "run_id")?,
        model: model(&v)?,
        ts: ts(&v),
        key_id: entropa_approvals::key_id(pubkey_hex),
    };
    platinum_fields(&d).map_err(|e| NodeError::Invalid(format!("{e:?}")))
}
/// Validate one evidence request into event fields.
pub fn evidence_event(request: &str, pubkey_hex: &str) -> Result<EventFields, NodeError> {
    let v = parse(request, &EVIDENCE_FIELDS)?;
    let rec = EvidenceRecord {
        kind: closed(Kind::parse(text(&v, "kind")?), "kind")?,
        label: closed(LabelCode::parse(text(&v, "label")?), "label")?,
        decision: closed(Decision::parse(text(&v, "decision")?), "decision")?,
        reason: closed(ReasonCode::parse(text(&v, "reason")?), "reason")?,
        control: closed(ControlCode::parse(text(&v, "control")?), "control")?,
        total: num(&v, "total")?,
        passed: num(&v, "passed")?,
        flagged: num(&v, "flagged")?,
        detail: text(&v, "detail")?,
        run_id: text(&v, "run_id")?,
        ts: ts(&v),
        key_id: entropa_approvals::key_id(pubkey_hex),
    };
    evidence_fields(&rec).map_err(|e| NodeError::Invalid(format!("{e:?}")))
}
/// Validate one council request into event fields. Model fields are optional, but all five come together.
pub fn council_event(request: &str, pubkey_hex: &str) -> Result<EventFields, NodeError> {
    let v = parse(request, &COUNCIL_FIELDS)?;
    let obj = v
        .as_object()
        .ok_or_else(|| NodeError::Invalid("request must be an object".into()))?;
    let keys = [
        "provider",
        "model_id",
        "input_tokens",
        "output_tokens",
        "cost_micro_usd",
    ];
    let model = match keys.iter().filter(|k| obj.contains_key(**k)).count() {
        0 => None,
        5 => Some(model(&v)?),
        _ => return invalid("model fields come together: provider, model_id, tokens and cost"),
    };
    let step = CouncilStep {
        label: closed(LabelCode::parse(text(&v, "label")?), "label")?,
        actor: closed(Handle::parse(text(&v, "actor")?), "actor")?,
        decision: closed(Decision::parse(text(&v, "decision")?), "decision")?,
        reason: closed(ReasonCode::parse(text(&v, "reason")?), "reason")?,
        subject: text(&v, "subject")?,
        session_id: text(&v, "session_id")?,
        model,
        ts: ts(&v),
        key_id: entropa_approvals::key_id(pubkey_hex),
    };
    council_fields(&step).map_err(|e| NodeError::Invalid(format!("{e:?}")))
}

/// Sign the event, append it to the ledger `dir/sub` with a signed checkpoint (signed BEFORE anything is written).
pub fn append(
    dir: &Path,
    sub: &str,
    signer: &dyn CheckpointSigner,
    fields: &EventFields,
) -> Result<Receipt, NodeError> {
    let label = fields.kind.as_str();
    let payload = encode_event(
        &sign_event(&Dyn(signer), fields).map_err(|e| NodeError::Io(format!("{e:?}")))?,
    )
    .map_err(|e| NodeError::Io(format!("{e:?}")))?;
    let record = encode_record(&payload, Some(label))
        .map_err(|_| NodeError::Invalid("record too large".into()))?;
    let mut store = FileStore::open(&dir.join(sub))
        .map_err(|e| NodeError::Store(StoreStage::Open, format!("{e:?}")))?;
    let mut tlog = TransparencyLog::new();
    for i in 0..store.len() {
        tlog.append(
            &store
                .record(i)
                .ok_or_else(|| NodeError::Io("store changed while reading".into()))?,
        );
    }
    tlog.append(&record);
    let cp = tlog
        .checkpoint_with(&Dyn(signer), fields.ts)
        .map_err(|e| NodeError::Io(e.to_string()))?;
    let index = store
        .append(&record)
        .map_err(|e| NodeError::Store(StoreStage::Append, format!("{e:?}")))?;
    store
        .put_checkpoint(&cp)
        .map_err(|e| NodeError::Store(StoreStage::Checkpoint, format!("{e:?}")))?;
    Ok(Receipt {
        index: index as u64,
        subject_hash: fields.subject_hash.clone(),
        size: cp.size as u64,
        root: hex::encode(cp.root),
    })
}

/// Re-read every record and checkpoint of `dir/sub` under `pubkey_hex`; `accept` says which event kinds the ledger may hold.
pub fn verify_ledger(
    dir: &Path,
    sub: &str,
    accept: fn(Kind) -> bool,
    pubkey_hex: &str,
) -> Result<String, NodeError> {
    // a directory without the ledger yet answers as the empty ledger it always did (it used to create the directory to get there; now nothing is created)
    if !dir.join(sub).is_dir() {
        return Ok("OK records=0 checkpoints=0".to_string());
    }
    let v = |m: String| Err(NodeError::Verify(m));
    let store = FileStore::open_read_only(&dir.join(sub))
        .map_err(|e| NodeError::Store(StoreStage::Open, format!("{e:?}")))?;
    for i in 0..store.len() {
        let Some(rec) = store.record(i) else {
            return v(format!("record {i} is missing"));
        };
        let Ok((payload, label)) = decode_record(&rec) else {
            return v(format!("record {i}: undecodable"));
        };
        let Ok(ev) = verify_event(&payload, pubkey_hex) else {
            return v(format!("record {i}: signature does not verify"));
        };
        if !accept(ev.fields.kind) || label.as_deref() != Some(ev.fields.kind.as_str()) {
            return v(format!("record {i}: not an accepted kind for this ledger"));
        }
    }
    let cps = store.checkpoints();
    for (n, cp) in cps.iter().enumerate() {
        if !cp.verify_signature(pubkey_hex) {
            return v(format!("checkpoint {n}: signature does not verify"));
        }
    }
    if cps.last().map_or(0, |c| c.size) != store.len() {
        return v("the last checkpoint does not cover every record".into());
    }
    Ok(format!(
        "OK records={} checkpoints={}",
        store.len(),
        cps.len()
    ))
}
