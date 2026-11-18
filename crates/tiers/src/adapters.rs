//! AT2b: the real parts behind the gate's traits (a stage record (not published)): an atomic meter, the egress guard, sealed retrieval and the signed evidence ledger.

use crate::append::IncrementalLedger;
use crate::{EgressGuard, Guard, Meter, MeterDeny, RecordSink, Retrieval, TierRecord};
use entropa_core::CheckpointSigner;
use entropa_egress::decide::{decide, Action as EgAction, Conversation, Request as EgRequest};
use entropa_egress::policy::{Policy, Tier as EgTier};
use entropa_egress::record::{EvidenceRequest, RecordSink as EgSink};
use entropa_ledger::{
    evidence_fields, ControlCode, Decision, EvidenceRecord, Kind, LabelCode, ReasonCode,
};
use entropa_tokens::Tier;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Default)]
struct Usage {
    spent: u64,
    calls: VecDeque<u64>,
}

/// An in-memory meter: usage is recorded and both caps are checked and recorded under ONE lock, so concurrent callers cannot overrun a cap.
#[derive(Default)]
pub struct MemoryMeter {
    state: Mutex<HashMap<String, Usage>>,
}

impl MemoryMeter {
    /// A new, empty meter.
    pub fn new() -> Self {
        MemoryMeter::default()
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Usage>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}
impl Meter for MemoryMeter {
    fn spent(&self, id: &str) -> u64 {
        self.lock().get(id).map_or(0, |u| u.spent)
    }
    fn calls_last_minute(&self, id: &str, now: u64) -> u64 {
        self.lock().get(id).map_or(0, |u| {
            u.calls
                .iter()
                .filter(|t| t.saturating_add(60) > now)
                .count() as u64
        })
    }
    fn try_reserve(
        &self,
        id: &str,
        cost: u64,
        spend_cap: u64,
        rate_cap: u64,
        now: u64,
    ) -> Result<(), MeterDeny> {
        let mut g = self.lock();
        let u = g.entry(id.to_string()).or_default();
        u.calls.retain(|t| t.saturating_add(60) > now);
        if u.spent.saturating_add(cost) > spend_cap {
            return Err(MeterDeny::Spend);
        }
        if u.calls.len() as u64 >= rate_cap {
            return Err(MeterDeny::Rate);
        }
        u.spent += cost;
        u.calls.push_back(now);
        Ok(())
    }
    fn release(&self, id: &str, cost: u64, now: u64) {
        let mut g = self.lock();
        if let Some(u) = g.get_mut(id) {
            u.spent = u.spent.saturating_sub(cost);
            if let Some(pos) = u.calls.iter().rposition(|t| *t == now) {
                u.calls.remove(pos);
            } else {
                u.calls.pop_back();
            }
        }
    }
}

struct NullSink;
impl EgSink for NullSink {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        Ok(())
    }
}

/// The egress guard over `entropa-egress`. A `Redact` is a `Block` here: the gate decides, it never rewrites a payload.
pub struct EgressAdapter {
    policy: Policy,
    destination: String,
    key: Vec<u8>,
}
impl EgressAdapter {
    /// Build it from a loaded (signed) egress policy, the model destination and the placeholder key.
    pub fn new(policy: Policy, destination: &str, key: &[u8]) -> Self {
        EgressAdapter {
            policy,
            destination: destination.to_string(),
            key: key.to_vec(),
        }
    }
}
impl EgressGuard for EgressAdapter {
    fn check(&self, tier: Tier, payload: &[u8]) -> Result<Guard, String> {
        if std::str::from_utf8(payload).is_err() {
            return Ok(Guard::Block);
        }
        let t = match tier {
            Tier::T0 => EgTier::T0,
            Tier::T1 => EgTier::T1,
            Tier::T2 => EgTier::T2,
            Tier::T3 => EgTier::T3,
        };
        let req = EgRequest {
            destination: self.destination.clone(),
            body: payload.to_vec(),
            body_is_json: false,
            attachments: vec![],
            headers: vec![],
        };
        let conv = Conversation {
            key: self.key.clone(),
            tail: String::new(),
            seen: vec![],
        };
        let d = decide(&req, &self.policy, t, &conv, &NullSink);
        Ok(if d.action() == EgAction::Allow {
            Guard::Allow
        } else {
            Guard::Block
        })
    }
}

/// The retrieval guard over `entropa-standards`: only a corpus hash that a held sealed version carries is searched, and only that version.
pub struct SealedRetrieval {
    r: entropa_standards::retrieve::Retriever,
}
impl SealedRetrieval {
    /// Wrap a retriever built from sealed corpora.
    pub fn new(r: entropa_standards::retrieve::Retriever) -> Self {
        SealedRetrieval { r }
    }
}
impl Retrieval for SealedRetrieval {
    fn read(&self, corpus: &str, query: &str) -> Result<Vec<u8>, String> {
        let version = self
            .r
            .version_info()
            .into_iter()
            .find(|(_, h)| h == corpus)
            .map(|(v, _)| v)
            .ok_or_else(|| "corpus hash not held".to_string())?;
        let res = self.r.search(
            query,
            Some(&version),
            5,
            &entropa_standards::retrieve::Config::default(),
        );
        serde_json::to_vec(&res).map_err(|_| "result not encodable".to_string())
    }
}

/// The record sink over the signed evidence ledger (`DIR/evidence-ledger`). One record per decision; the checkpoint is signed BEFORE any byte is written, so a failing signer leaves
/// the ledger unchanged. Closed vocabulary only; the precise word goes in the hashed-and-dropped `detail`. Appends go through `IncrementalLedger` (no replay of the ledger).
pub struct LedgerSink {
    ledger: IncrementalLedger,
    key_id: String,
}
impl LedgerSink {
    /// Append to the evidence ledger in `dir`, signed by `signer` (the crate holds no key).
    pub fn new(dir: PathBuf, signer: Box<dyn CheckpointSigner>) -> Self {
        let key_id = entropa_approvals::key_id(&signer.pubkey_hex());
        LedgerSink {
            ledger: IncrementalLedger::new(dir, signer),
            key_id,
        }
    }
}
fn reason_for(r: &TierRecord) -> ReasonCode {
    let word = if r.decision == "allowed" {
        "within_limits"
    } else {
        match r.reason.as_str() {
            "egress_blocked" => "guard_refused",
            "spend_cap" | "rate_cap" | "tier_forbids" | "policy_denied" | "policy_error"
            | "egress_error" | "retrieval_error" | "record_failed" | "internal_error" => {
                "policy_deny"
            }
            _ => "gate_denied",
        }
    };
    ReasonCode::parse(word).unwrap_or(ReasonCode::GateDenied)
}
impl RecordSink for LedgerSink {
    fn write(&self, r: &TierRecord) -> Result<(), String> {
        let allowed = r.decision == "allowed";
        let detail = format!(
            "word={};tier={};action={};token={};policy={}",
            if allowed {
                "allowed"
            } else {
                r.reason.as_str()
            },
            r.tier.unwrap_or("none"),
            r.action,
            r.token_hash.as_deref().unwrap_or("none"),
            r.policy_hash
        );
        let rec = EvidenceRecord {
            kind: Kind::parse("evidence.policy").ok_or("kind")?,
            label: LabelCode::parse("policy_verdict").ok_or("label")?,
            decision: if allowed {
                Decision::Allow
            } else {
                Decision::Deny
            },
            reason: reason_for(r),
            control: ControlCode::parse("hitrust_01_access_control").ok_or("control")?,
            total: 1,
            passed: u64::from(allowed),
            flagged: u64::from(!allowed),
            detail: &detail,
            run_id: &r.request_hash,
            ts: r.ts,
            key_id: self.key_id.clone(),
        };
        let fields = evidence_fields(&rec).map_err(|e| format!("{e:?}"))?;
        self.ledger.append_event(&fields).map(|_| ())
    }
}
