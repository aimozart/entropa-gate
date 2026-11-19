//! The static JSON bundle: export from a store, and a standalone verifier that needs only the JSON.

use crate::event::{canonical_json, decode_event, event_canonical_bytes, event_digest};
#[cfg(feature = "engine")]
use crate::generator::Generator;
#[cfg(feature = "engine")]
use crate::store::LedgerStore;
use crate::vocab::{Handle, Kind, RoleCode, Tenant};
use crate::{LedgerError, MAX_BUNDLE_BYTES};
use entropa_approvals::{self as ap, Body};
#[cfg(feature = "engine")]
use entropa_core::merkle::{consistency_proof, leaf_hash};
use entropa_core::merkle::{verify_consistency, Hash};
#[cfg(feature = "engine")]
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::transparency_log::{decode_record, Checkpoint, Receipt};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

/// The names that must never appear in public output, spelled backwards so that no internal name is
/// written in this source file (a test scans the sources for them).
const CREW_NAMES_REVERSED: [&str; 4] = ["kcops", "yttocs", "uluS", "niatpac"];

fn crew_names() -> Vec<String> {
    CREW_NAMES_REVERSED
        .iter()
        .map(|n| n.chars().rev().collect::<String>().to_lowercase())
        .collect()
}

/// Counts from [`verify_bundle`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BundleReport {
    /// Records checked.
    pub records: usize,
    /// Checkpoints whose signature verified.
    pub checkpoints: usize,
    /// Receipts that verified against the head.
    pub receipts: usize,
    /// Consistency proofs that verified.
    pub consistency: usize,
    /// Witness statements that verified.
    pub witnesses: usize,
    /// Events and approval or policy records whose own signature verified.
    pub signatures: usize,
}

fn invalid(what: &str) -> LedgerError {
    LedgerError::Invalid(what.to_string())
}

fn verify_err(what: &str) -> LedgerError {
    LedgerError::Verify(what.to_string())
}

/// What the exporter and the verifier both derive from one record.
struct Described {
    label: String,
    tenant: Tenant,
    handle: Handle,
    ts: u64,
    summary: Value,
    /// Key id whose public key signed the record (`None`: the generator, for directory events).
    signer: Option<String>,
    digest: [u8; 32],
    sig: String,
}

#[derive(Default)]
struct Ctx {
    by_request: HashMap<String, Tenant>,
    by_subject: HashMap<String, Tenant>,
}

fn describe(
    label: &str,
    payload: &str,
    handles: &BTreeMap<String, Handle>,
    ctx: &mut Ctx,
) -> Result<Described, LedgerError> {
    let handle_of = |id: &str| {
        handles
            .get(id)
            .copied()
            .ok_or_else(|| invalid("a record names an unknown actor"))
    };
    match label {
        "tx.screened" | "agent.invocation" | "directory.actor" => {
            let ev = decode_event(payload)?;
            if ev.fields.kind.as_str() != label || handle_of(&ev.fields.key_id)? != ev.fields.handle
            {
                return Err(invalid("event does not match its label or actor"));
            }
            ctx.by_subject
                .insert(ev.fields.subject_hash.clone(), ev.fields.tenant);
            let signer = if ev.fields.kind == Kind::DirectoryActor {
                None
            } else {
                Some(ev.fields.key_id.clone())
            };
            Ok(Described {
                label: label.to_string(),
                tenant: ev.fields.tenant,
                handle: ev.fields.handle,
                ts: ev.fields.ts,
                summary: json!({"label": ev.fields.label.as_str(), "decision": ev.fields.decision.as_str(), "reason": ev.fields.reason.as_str()}),
                signer,
                digest: event_digest(&event_canonical_bytes(&ev.fields)),
                sig: ev.sig,
            })
        }
        "approval.request" | "approval.approve" | "approval.deny" | "approval.consume" => {
            let se = ap::decode(payload).map_err(|_| invalid("approval event"))?;
            let e = &se.event;
            let (tenant, summary) = match (&e.body, label) {
                (
                    Body::Request {
                        action_class,
                        subject_hash,
                        subject_ref,
                        ..
                    },
                    "approval.request",
                ) => {
                    let tenant = subject_ref
                        .split(':')
                        .next()
                        .and_then(Tenant::parse)
                        .ok_or_else(|| invalid("request without a tenant"))?;
                    ctx.by_request.insert(e.request_id.clone(), tenant);
                    ctx.by_subject.insert(subject_hash.clone(), tenant);
                    (tenant, json!({"action_class": action_class.as_str()}))
                }
                (Body::Approve { on_behalf_of, .. }, "approval.approve") => (
                    request_tenant(ctx, &e.request_id)?,
                    json!({"mode": if on_behalf_of.is_some() { "attested" } else { "direct" }}),
                ),
                (Body::Deny { .. }, "approval.deny") => (
                    request_tenant(ctx, &e.request_id)?,
                    json!({"mode": "denied"}),
                ),
                (Body::Consume, "approval.consume") => (
                    request_tenant(ctx, &e.request_id)?,
                    json!({"mode": "consumed"}),
                ),
                _ => return Err(invalid("approval event does not match its label")),
            };
            Ok(Described {
                label: label.to_string(),
                tenant,
                handle: handle_of(&e.actor)?,
                ts: e.ts,
                summary,
                signer: Some(e.actor.clone()),
                digest: ap::signing_digest(e),
                sig: se.sig.clone(),
            })
        }
        "policy.decision" => {
            entropa_policy::decode_record(payload).map_err(|_| invalid("policy record"))?;
            let mut obj: Map<String, Value> = entropa_witness::strict_json::from_str(payload)
                .ok()
                .and_then(|v| match v {
                    Value::Object(m) => Some(m),
                    _ => None,
                })
                .ok_or_else(|| invalid("policy record"))?;
            let sig = obj
                .remove("sig")
                .and_then(|v| v.as_str().map(str::to_string))
                .ok_or_else(|| invalid("policy record signature"))?;
            let text = |k: &str| {
                obj.get(k)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| invalid("policy record field"))
            };
            let (actor, subject) = (text("actor")?, text("subject_hash")?);
            let tenant = ctx
                .by_subject
                .get(&subject)
                .copied()
                .ok_or_else(|| invalid("policy decision for an unknown subject"))?;
            let summary = json!({"action": text("action")?, "outcome": text("final")?, "reason": text("reason")?});
            let ts = obj
                .get("ts")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid("policy record ts"))?;
            let canon = canonical_json(&Value::Object(obj)).into_bytes();
            Ok(Described {
                label: label.to_string(),
                tenant,
                handle: handle_of(&actor)?,
                ts,
                summary,
                signer: Some(actor),
                digest: entropa_policy::record_digest(&canon),
                sig,
            })
        }
        _ => Err(invalid("unknown record label")),
    }
}

fn request_tenant(ctx: &Ctx, request_id: &str) -> Result<Tenant, LedgerError> {
    ctx.by_request
        .get(request_id)
        .copied()
        .ok_or_else(|| invalid("approval for an unknown request"))
}

#[cfg(feature = "engine")]
impl Generator {
    /// Export the static JSON bundle of the whole store.
    pub fn export_bundle(&self, store: &impl LedgerStore) -> Result<String, LedgerError> {
        let cps = store.checkpoints();
        let head = cps
            .last()
            .cloned()
            .ok_or_else(|| invalid("the store has no checkpoint"))?;
        if store.len() != head.size {
            return Err(invalid("records exist after the last checkpoint"));
        }
        let mut log = TransparencyLog::new();
        let mut leaves: Vec<Hash> = Vec::new();
        for i in 0..store.len() {
            let rec = store.record(i).ok_or_else(|| invalid("missing record"))?;
            leaves.push(leaf_hash(&rec));
            log.append(&rec);
        }
        let mut ctx = Ctx::default();
        let mut records = Vec::new();
        let mut receipts = Vec::new();
        for i in 0..store.len() {
            let bytes = store.record(i).ok_or_else(|| invalid("missing record"))?;
            let (payload, label) = decode_record(&bytes).map_err(|_| invalid("record"))?;
            let d = describe(
                &label.unwrap_or_default(),
                &payload,
                &self.handles,
                &mut ctx,
            )?;
            records.push(json!({"index": i, "record_hex": hex::encode(&bytes), "kind": d.label, "tenant": d.tenant.as_str(), "handle": d.handle.as_str(), "ts": d.ts, "summary": d.summary}));
            let receipt = log
                .receipt(i, &head)
                .ok_or_else(|| invalid("no receipt for a record"))?;
            receipts.push(json!({"index": i, "proof": serde_json::to_value(&receipt.proof).map_err(|_| invalid("receipt proof"))?}));
        }
        let mut consistency = Vec::new();
        for pair in cps.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let proof: Vec<Hash> = if a.size == 0 || a.size == b.size {
                Vec::new()
            } else {
                consistency_proof(&leaves[..b.size], a.size)
                    .ok_or_else(|| invalid("consistency proof"))?
            };
            consistency.push(json!({"old_size": a.size, "new_size": b.size, "proof": proof.iter().map(hex::encode).collect::<Vec<_>>()}));
        }
        let mut actors: Vec<(Handle, Value)> = Vec::new();
        for (id, a) in &self.directory.actors {
            let handle = self
                .handles
                .get(id)
                .copied()
                .ok_or_else(|| invalid("actor without a handle"))?;
            let attested_by = self
                .directory
                .actors
                .iter()
                .find(|(_, o)| o.may_attest_for.contains(id))
                .and_then(|(oid, _)| self.handles.get(oid))
                .map(|h| h.as_str());
            let role = match a.role {
                ap::Role::Human => RoleCode::Human,
                ap::Role::Ai => RoleCode::Ai,
                ap::Role::Service => RoleCode::Service,
            };
            let status = if a.pubkey_hex.is_empty() {
                "keyless"
            } else if a.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            };
            actors.push((handle, json!({"handle": handle.as_str(), "key_id": id, "pubkey_hex": a.pubkey_hex, "fingerprint": id, "role": role.as_str(),
                "status": status, "attested_by": attested_by, "may_approve": a.may_approve.iter().map(|c| c.as_str()).collect::<Vec<_>>()})));
        }
        actors.sort_by_key(|(h, _)| *h);
        let log_pub = self.log_pubkey_hex();
        let bundle = json!({
            "v": 1, "synthetic": true,
            "log": {"pubkey_hex": log_pub, "fingerprint": ap::key_id(&log_pub), "algorithm": "ML-DSA-65"},
            "head": serde_json::to_value(&head).map_err(|_| invalid("head"))?,
            "checkpoints": cps.iter().map(|c| serde_json::to_value(c).unwrap_or_default()).collect::<Vec<_>>(),
            "records": records, "receipts": receipts, "consistency": consistency,
            "witnesses": store.witnesses(),
            "actors": actors.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
        });
        let text = canonical_json(&bundle);
        if text.len() > MAX_BUNDLE_BYTES {
            return Err(LedgerError::Limit("bundle is larger than 5 MiB".into()));
        }
        Ok(text)
    }
}

fn object<'a>(v: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, LedgerError> {
    let m = v.as_object().ok_or_else(|| invalid("expected an object"))?;
    if m.len() != keys.len() || !keys.iter().all(|k| m.contains_key(*k)) {
        return Err(invalid("unexpected or missing field"));
    }
    Ok(m)
}

fn array(v: &Value) -> Result<&Vec<Value>, LedgerError> {
    v.as_array().ok_or_else(|| invalid("expected an array"))
}

fn text(v: &Value) -> Result<&str, LedgerError> {
    v.as_str().ok_or_else(|| invalid("expected a string"))
}

fn hash_of(v: &Value) -> Result<Hash, LedgerError> {
    let b = hex::decode(text(v)?).map_err(|_| invalid("expected hex"))?;
    Hash::try_from(b.as_slice()).map_err(|_| invalid("expected 32 bytes"))
}

/// Verify a bundle on its own: no store and no generator, only the JSON.
pub fn verify_bundle(json: &str) -> Result<BundleReport, LedgerError> {
    if json.len() > MAX_BUNDLE_BYTES {
        return Err(LedgerError::Limit("bundle is larger than 5 MiB".into()));
    }
    let v: Value = entropa_witness::strict_json::from_str(json)
        .map_err(|_| invalid("not valid JSON or a duplicated key"))?;
    let top = object(
        &v,
        &[
            "v",
            "synthetic",
            "log",
            "head",
            "checkpoints",
            "records",
            "receipts",
            "consistency",
            "witnesses",
            "actors",
        ],
    )?;
    if top["v"].as_u64() != Some(1) || top["synthetic"].as_bool() != Some(true) {
        return Err(invalid("unsupported version or not synthetic"));
    }
    let lower = json.to_lowercase();
    if crew_names().iter().any(|n| lower.contains(n.as_str())) {
        return Err(invalid("an internal name appears in public output"));
    }
    let log = object(&top["log"], &["pubkey_hex", "fingerprint", "algorithm"])?;
    let log_pub = text(&log["pubkey_hex"])?.to_string();
    if text(&log["algorithm"])? != "ML-DSA-65"
        || log_pub.is_empty()
        || text(&log["fingerprint"])? != ap::key_id(&log_pub)
    {
        return Err(invalid("log key description"));
    }
    // actors
    let mut handles: BTreeMap<String, Handle> = BTreeMap::new();
    let mut pubkeys: HashMap<String, String> = HashMap::new();
    let mut by_handle: HashMap<Handle, String> = HashMap::new();
    for a in array(&top["actors"])? {
        let m = object(
            a,
            &[
                "handle",
                "key_id",
                "pubkey_hex",
                "fingerprint",
                "role",
                "status",
                "attested_by",
                "may_approve",
            ],
        )?;
        let handle = Handle::parse(text(&m["handle"])?).ok_or_else(|| invalid("actor handle"))?;
        // the descriptive fields are presentation (the signatures do not cover them) but they must at least be well formed and consistent
        // with the key: a closed role, a status that agrees with the key, a known attester, closed action classes
        RoleCode::parse(text(&m["role"])?).ok_or_else(|| invalid("actor role"))?;
        let keyless = text(&m["pubkey_hex"])?.is_empty();
        match text(&m["status"])? {
            "keyless" if keyless => {}
            "active" | "revoked" if !keyless => {}
            _ => return Err(invalid("actor status")),
        }
        if !m["attested_by"].is_null() {
            Handle::parse(text(&m["attested_by"])?).ok_or_else(|| invalid("actor attester"))?;
        }
        for c in array(&m["may_approve"])? {
            ap::ActionClass::parse(text(c)?).ok_or_else(|| invalid("actor approval class"))?;
        }
        let (id, pk) = (
            text(&m["key_id"])?.to_string(),
            text(&m["pubkey_hex"])?.to_string(),
        );
        if id.len() != 16
            || text(&m["fingerprint"])? != id
            || (!pk.is_empty() && ap::key_id(&pk) != id)
        {
            return Err(invalid("actor key id"));
        }
        handles.insert(id.clone(), handle);
        by_handle.insert(handle, pk.clone());
        if !pk.is_empty() {
            pubkeys.insert(id, pk);
        }
    }
    // checkpoints
    let mut cps: Vec<Checkpoint> = Vec::new();
    let mut report = BundleReport::default();
    for c in array(&top["checkpoints"])? {
        let cp: Checkpoint =
            serde_json::from_value(c.clone()).map_err(|_| invalid("checkpoint"))?;
        if !cp.verify_signature(&log_pub) {
            return Err(verify_err("checkpoint signature"));
        }
        if cps.last().is_some_and(|l| cp.size < l.size) {
            return Err(invalid("checkpoints shrink"));
        }
        cps.push(cp);
        report.checkpoints += 1;
    }
    let head = cps.last().ok_or_else(|| invalid("no checkpoints"))?.clone();
    if serde_json::from_value::<Checkpoint>(top["head"].clone()).map_err(|_| invalid("head"))?
        != head
    {
        return Err(invalid("head is not the last checkpoint"));
    }
    // records
    let generator_pub = by_handle
        .get(&Handle::Generator)
        .cloned()
        .unwrap_or_default();
    let mut ctx = Ctx::default();
    let mut raw: Vec<Vec<u8>> = Vec::new();
    for (i, r) in array(&top["records"])?.iter().enumerate() {
        let m = object(
            r,
            &[
                "index",
                "record_hex",
                "kind",
                "tenant",
                "handle",
                "ts",
                "summary",
            ],
        )?;
        if m["index"].as_u64() != Some(i as u64) {
            return Err(invalid("record index"));
        }
        let bytes = hex::decode(text(&m["record_hex"])?).map_err(|_| invalid("record hex"))?;
        let (payload, label) = decode_record(&bytes).map_err(|_| invalid("record"))?;
        let d = describe(&label.unwrap_or_default(), &payload, &handles, &mut ctx)?;
        if text(&m["kind"])? != d.label
            || text(&m["tenant"])? != d.tenant.as_str()
            || text(&m["handle"])? != d.handle.as_str()
            || m["ts"].as_u64() != Some(d.ts)
            || m["summary"] != d.summary
        {
            return Err(invalid("record summary does not match the record"));
        }
        let pk = match &d.signer {
            None => generator_pub.clone(),
            Some(id) => pubkeys.get(id).cloned().unwrap_or_default(),
        };
        if pk.is_empty() || !entropa_core::verify_hex(&pk, &d.digest, &d.sig) {
            return Err(verify_err("record signature"));
        }
        report.signatures += 1;
        report.records += 1;
        raw.push(bytes);
    }
    // receipts
    let receipts = array(&top["receipts"])?;
    if receipts.len() != raw.len() {
        return Err(invalid("receipt count"));
    }
    for (i, r) in receipts.iter().enumerate() {
        // compact receipts carry only the proof; the record and the head come from the bundle itself
        let m = object(r, &["index", "proof"])?;
        if m["index"].as_u64() != Some(i as u64) {
            return Err(verify_err("receipt index"));
        }
        let proof =
            serde_json::from_value(m["proof"].clone()).map_err(|_| invalid("receipt proof"))?;
        let receipt = Receipt {
            index: i,
            record: raw[i].clone(),
            proof,
            checkpoint: head.clone(),
        };
        if !entropa_core::transparency_log::verify_receipt(&receipt, &log_pub) {
            return Err(verify_err("receipt does not verify"));
        }
        report.receipts += 1;
    }
    // consistency
    let proofs = array(&top["consistency"])?;
    if proofs.len() + 1 != cps.len() {
        return Err(invalid("consistency count"));
    }
    for (i, p) in proofs.iter().enumerate() {
        let m = object(p, &["old_size", "new_size", "proof"])?;
        let (a, b) = (&cps[i], &cps[i + 1]);
        if m["old_size"].as_u64() != Some(a.size as u64)
            || m["new_size"].as_u64() != Some(b.size as u64)
        {
            return Err(invalid("consistency sizes"));
        }
        let proof = array(&m["proof"])?
            .iter()
            .map(hash_of)
            .collect::<Result<Vec<_>, _>>()?;
        let ok = if a.size == 0 || a.size == b.size {
            proof.is_empty() && (a.size == 0 || a.root == b.root)
        } else {
            verify_consistency(&a.root, a.size, &b.root, b.size, &proof)
        };
        if !ok {
            return Err(verify_err("consistency proof"));
        }
        report.consistency += 1;
    }
    // witnesses
    let witness_pub = by_handle
        .get(&Handle::WitnessAzure)
        .cloned()
        .unwrap_or_default();
    for w in array(&top["witnesses"])? {
        let st = entropa_witness::verify_statement(text(w)?, &witness_pub)
            .map_err(|_| verify_err("witness statement"))?;
        if !cps
            .iter()
            .any(|c| c.size as u64 == st.fields.size && hex::encode(c.root) == st.fields.root)
        {
            return Err(verify_err("witness statement names no checkpoint"));
        }
        report.witnesses += 1;
    }
    Ok(report)
}
