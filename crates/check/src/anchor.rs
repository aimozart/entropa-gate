//! Anchoring a pre-registration in a local ledger: ONE hash-only record per pre-registration in the evidence ledger of a node directory (the directory of an initialised
//! entropa-gate or entropa-platinum node: `platinum.key` and `evidence-ledger/`). The record is `evidence.change` / `prereg_committed`; its detail (`entropa-prereg-v1|<sha256 of the
//! record>`) is hashed and dropped by the ledger, so only a BLAKE3 subject hash is stored. Ordering relative to later records is fixed by the ledger's signed checkpoints.
use crate::Refusal;
use entropa_core::transparency_log::decode_record;
use entropa_ledger::{
    decode_event, evidence_fields, ControlCode, Decision, EvidenceRecord, FileStore, Kind,
    LabelCode, LedgerStore, ReasonCode,
};
use std::path::Path;

const SUB: &str = "evidence-ledger";

fn fields_for(
    prereg_text: &str,
    key_id: String,
    ts: u64,
) -> Result<entropa_ledger::EventFields, Refusal> {
    let sha = crate::sha256_hex(prereg_text.as_bytes());
    let detail = format!("entropa-prereg-v1|{sha}");
    let run_id = format!("prereg-{}", &sha[..24]);
    evidence_fields(&EvidenceRecord {
        kind: Kind::EvidenceChange,
        label: LabelCode::PreregCommitted,
        decision: Decision::Info,
        reason: ReasonCode::None,
        control: ControlCode::Hitrust10Sdlc,
        total: 1,
        passed: 1,
        flagged: 0,
        detail: &detail,
        run_id: &run_id,
        ts,
        key_id,
    })
    .map_err(|_| Refusal::new("the anchor record could not be built"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn holds(dir: &Path, subject_hash: &str) -> bool {
    let Ok(store) = FileStore::open_read_only(&dir.join(SUB)) else {
        return false;
    };
    (0..store.len()).any(|i| {
        store
            .record(i)
            .and_then(|r| decode_record(&r).ok())
            .and_then(|(payload, _)| decode_event(&payload).ok())
            .is_some_and(|ev| {
                ev.fields.label == LabelCode::PreregCommitted
                    && ev.fields.subject_hash == subject_hash
            })
    })
}

/// Append the record for `prereg_text` to the evidence ledger of the node directory `dir`; returns the record index.
pub fn record(dir: &Path, prereg_text: &str) -> Result<u64, Refusal> {
    let probe = entropa_release::cli::load_key(&dir.join("platinum.key")).map_err(Refusal)?;
    let pk = probe.pubkey_hex();
    let f = fields_for(prereg_text, entropa_approvals::key_id(&pk), now())?;
    if holds(dir, &f.subject_hash) {
        return Err(Refusal::new(
            "this pre-registration is already anchored in that ledger",
        ));
    }
    let r = entropa_nodecore::append(dir, SUB, &probe, &f)
        .map_err(|_| Refusal::new("the anchor record could not be appended"))?;
    Ok(r.index)
}

/// True only when the ledger of `dir` verifies from start to end under the key of `dir` AND holds the anchor record of `prereg_text`.
pub fn check(dir: &Path, prereg_text: &str) -> bool {
    let Ok(probe) = entropa_release::cli::load_key(&dir.join("platinum.key")) else {
        return false;
    };
    let pk = probe.pubkey_hex();
    if !dir.join(SUB).is_dir()
        || entropa_nodecore::verify_ledger(dir, SUB, Kind::is_evidence, &pk).is_err()
    {
        return false;
    }
    let Ok(f) = fields_for(prereg_text, entropa_approvals::key_id(&pk), 0) else {
        return false;
    };
    holds(dir, &f.subject_hash)
}
