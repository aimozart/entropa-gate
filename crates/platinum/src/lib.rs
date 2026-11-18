//! Library behind the `entropa-platinum` CLI and service: records platinum-layer AI decisions as signed, data-minimal ledger events.
//!
//! ```text
//! entropa-platinum init   DIR   create the key (mode 0600) and the ledger store
//! entropa-platinum log    DIR   read one JSON request on stdin, append a signed event + checkpoint
//! entropa-platinum verify DIR   re-read everything and check every signature and checkpoint
//! entropa-platinum pubkey DIR   print the public key (hex)
//! ```
//!
//! The raw question, SQL, rows and answers are hashed and dropped; only the hash, closed codes and
//! model counts are stored (docs/ARCHITECTURE-EXPLORER.md). The local key is a demo key kept in a
//! file; the online stage uses a managed KMS key instead.

use entropa_core::merkle::leaf_hash;
use entropa_core::transparency_log::decode_record;
use entropa_core::{CheckpointSigner, Probe};
use entropa_ledger::{decode_event, plain_english, EventFields, FileStore, Kind, LedgerStore};
use serde_json::{json, Value};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub mod serve;
mod witnesses;
pub use witnesses::{kept_statements, sync_witnesses};

/// Result with a short, input-free error text.
pub type Res<T> = Result<T, String>;

fn fail<T>(msg: &str) -> Res<T> {
    Err(msg.to_string())
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join("platinum.key")
}

/// Load the signing key (file in the directory, or the mounted secret named by `PLATINUM_KEY_FILE`).
pub fn load_probe(dir: &Path) -> Res<Probe> {
    // PLATINUM_KEY_FILE points at a mounted secret (a managed secret store sets its own permissions).
    let external = std::env::var_os("PLATINUM_KEY_FILE").map(PathBuf::from);
    let p = external.clone().unwrap_or_else(|| key_path(dir));
    let meta = std::fs::metadata(&p).map_err(|_| "no key file (run init first)".to_string())?;
    if external.is_none() && meta.permissions().mode() & 0o077 != 0 {
        return fail("the key file must not be readable by group or others (chmod 600)");
    }
    let seed = std::fs::read_to_string(&p).map_err(|_| "cannot read the key file".to_string())?;
    Probe::from_signing_key_hex(seed.trim())
        .ok_or_else(|| "the key file is not a valid key".to_string())
}

/// The node's signer: a Google Cloud KMS ML-DSA-65 key when `ENTROPA_GCP_KMS_KEY` names one, otherwise the key
/// file in the node directory (or the secret named by `PLATINUM_KEY_FILE`).
pub fn node_signer(dir: &Path) -> Res<Box<dyn CheckpointSigner>> {
    if std::env::var_os("ENTROPA_GCP_KMS_KEY").is_some() {
        let cfg = entropa_kms::gcp::GcpKmsConfig::from_vars(|k| std::env::var(k).ok())
            .map_err(|e| e.to_string())?;
        let signer = entropa_kms::KmsSigner::new(
            entropa_kms::gcp::GcpKmsClient::new(cfg),
            entropa_kms::KeySpec::MlDsa65,
        )
        .map_err(|e| e.to_string())?;
        return Ok(Box::new(signer));
    }
    Ok(Box::new(load_probe(dir)?))
}

/// Create the key (mode 0600) and the ledger directory.
pub fn init(dir: &Path) -> Res<()> {
    std::fs::create_dir_all(dir).map_err(|_| "cannot create the directory".to_string())?;
    let p = key_path(dir);
    if p.exists() {
        return fail("already initialised");
    }
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|_| "no random source".to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&p)
        .map_err(|_| "cannot create the key file".to_string())?;
    std::io::Write::write_all(&mut f, format!("{}\n", hex::encode(seed)).as_bytes())
        .map_err(|_| "cannot write the key file".to_string())?;
    std::fs::create_dir_all(dir.join("ledger"))
        .map_err(|_| "cannot create the store".to_string())?;
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Validate one JSON request, append the signed event and a signed checkpoint; returns index, hash, size, root.
/// Like [`log`] with an explicit signer (the managed key in the cloud).
pub fn log_with(dir: &Path, signer: &dyn CheckpointSigner, request: &str) -> Res<Value> {
    let fields = entropa_nodecore::decision_fields(request, &signer.pubkey_hex())
        .map_err(|e| e.to_string())?;
    append_fields(dir, "ledger", signer, &fields)
}

/// Validate one JSON request, append the signed event and a signed checkpoint; returns index, hash, size, root.
pub fn log(dir: &Path, request: &str) -> Res<Value> {
    log_with(dir, &*node_signer(dir)?, request)
}

/// Sign `fields`, append the event to the ledger in `dir/sub` and add a signed checkpoint.
fn append_fields(
    dir: &Path,
    sub: &str,
    signer: &dyn CheckpointSigner,
    fields: &EventFields,
) -> Res<Value> {
    let r = entropa_nodecore::append(dir, sub, signer, fields).map_err(|e| e.to_string())?;
    Ok(json!({"index": r.index, "subject_hash": r.subject_hash, "size": r.size, "root": r.root}))
}

/// Validate one evidence request (JSON) and append it, signed, to the separate evidence ledger.
/// Like [`log_evidence`] with an explicit signer.
pub fn log_evidence_with(dir: &Path, signer: &dyn CheckpointSigner, request: &str) -> Res<Value> {
    let fields = entropa_nodecore::evidence_event(request, &signer.pubkey_hex())
        .map_err(|e| e.to_string())?;
    append_fields(dir, "evidence-ledger", signer, &fields)
}

/// Validate one evidence request (JSON) and append it, signed, to the separate evidence ledger.
pub fn log_evidence(dir: &Path, request: &str) -> Res<Value> {
    log_evidence_with(dir, &*node_signer(dir)?, request)
}

/// Re-read every record and checkpoint and check every signature; returns an `OK records=N checkpoints=M` line.
pub fn verify(dir: &Path) -> Res<String> {
    verify_with(dir, &node_signer(dir)?.pubkey_hex())
}

/// Verify the AI-decision ledger under an explicit public key.
pub fn verify_with(dir: &Path, pubkey_hex: &str) -> Res<String> {
    verify_in(dir, "ledger", |k| k == Kind::PlatinumDecision, pubkey_hex)
}

/// Validate one council step (JSON) and append it, signed, to the separate council ledger.
/// Model fields are optional, but all five come together.
pub fn log_council_with(dir: &Path, signer: &dyn CheckpointSigner, request: &str) -> Res<Value> {
    let fields = entropa_nodecore::council_event(request, &signer.pubkey_hex())
        .map_err(|e| e.to_string())?;
    append_fields(dir, "council-ledger", signer, &fields)
}

/// Like [`log_council_with`] with the node's own signer.
pub fn log_council(dir: &Path, request: &str) -> Res<Value> {
    log_council_with(dir, &*node_signer(dir)?, request)
}

/// Verify the council ledger.
pub fn verify_council(dir: &Path) -> Res<String> {
    verify_council_with(dir, &node_signer(dir)?.pubkey_hex())
}

/// Verify the council ledger under an explicit public key.
pub fn verify_council_with(dir: &Path, pubkey_hex: &str) -> Res<String> {
    verify_in(
        dir,
        "council-ledger",
        |k| k == Kind::CouncilStep,
        pubkey_hex,
    )
}

/// Export the council ledger as a public, data-minimal bundle (same shape as the other bundles).
pub fn export_council(dir: &Path) -> Res<Value> {
    export_in(dir, "council-ledger", verify_council(dir)?)
}

/// Verify the evidence ledger (kinds: pipeline run, control check, access, change, policy).
pub fn verify_evidence(dir: &Path) -> Res<String> {
    verify_evidence_with(dir, &node_signer(dir)?.pubkey_hex())
}

/// Verify the evidence ledger under an explicit public key.
pub fn verify_evidence_with(dir: &Path, pubkey_hex: &str) -> Res<String> {
    verify_in(dir, "evidence-ledger", Kind::is_evidence, pubkey_hex)
}

/// Export the evidence ledger as a public, data-minimal bundle: every record's codes, counts and hashes, the
/// signed checkpoints and the public key. The ledger is verified first; a failed verification is an error.
pub fn export_evidence(dir: &Path) -> Res<Value> {
    export_in(dir, "evidence-ledger", verify_evidence(dir)?)
}

/// Export the AI-decision ledger the same way (codes, model metadata, hashes, plain English; no text).
pub fn export_decisions(dir: &Path) -> Res<Value> {
    export_in(dir, "ledger", verify(dir)?)
}

fn export_in(dir: &Path, sub: &str, verified: String) -> Res<Value> {
    let pubkey = node_signer(dir)?.pubkey_hex();
    if let Ok(urls) = std::env::var("WITNESS_URLS") {
        let list: Vec<String> = urls
            .split(',')
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect();
        for r in sync_witnesses(dir, sub, &list) {
            if let Err(e) = r {
                eprintln!("witness sync ({sub}) failed: {e}"); // best effort: a witness being down never blocks an export
            }
        }
    }
    let store = FileStore::open(&dir.join(sub)).map_err(|e| format!("{e:?}"))?;
    let mut records = Vec::new();
    for i in 0..store.len() {
        let rec = store.record(i).ok_or("missing record")?;
        let (payload, _) = decode_record(&rec).map_err(|_| format!("record {i}: undecodable"))?;
        let ev = decode_event(&payload).map_err(|_| format!("record {i}: undecodable event"))?;
        let f = &ev.fields;
        let mut r = json!({
            "index": i, "ts": f.ts, "plain": plain_english(f), "kind": f.kind.as_str(), "label": f.label.as_str(),
            "record_hex": hex::encode(&rec), "payload": payload,
            "decision": f.decision.as_str(), "reason": f.reason.as_str(),
            "subject_hash": f.subject_hash, "leaf_hash": hex::encode(leaf_hash(&rec)),
            "key_id": f.key_id, "handle": f.handle.as_str(), "tenant": f.tenant.as_str(),
            "sig_prefix": ev.sig.chars().take(32).collect::<String>(), "sig_len": ev.sig.len(),
        });
        if let (Some(e), Some(m)) = (f.evidence.as_ref(), r.as_object_mut()) {
            m.insert("control".into(), json!(e.control.as_str()));
            m.insert("total".into(), json!(e.total));
            m.insert("passed".into(), json!(e.passed));
            m.insert("flagged".into(), json!(e.flagged));
        }
        if let (Some(a), Some(m)) = (f.agent.as_ref(), r.as_object_mut()) {
            m.insert("provider".into(), json!(a.provider.as_str()));
            m.insert("model_id".into(), json!(a.model_id));
            m.insert("input_tokens".into(), json!(a.input_tokens));
            m.insert("output_tokens".into(), json!(a.output_tokens));
            m.insert("cost_micro_usd".into(), json!(a.cost_micro_usd));
        }
        records.push(r);
    }
    let checkpoints: Vec<Value> = store
        .checkpoints()
        .iter()
        .map(|c| {
            json!({"size": c.size, "root": hex::encode(c.root), "timestamp": c.timestamp,
            "signature": c.signature, "sig_prefix": c.signature.chars().take(32).collect::<String>()})
        })
        .collect();
    Ok(json!({
        "v": 1, "generated_at": now(), "algorithm": "ML-DSA-65", "synthetic": true,
        "pubkey": pubkey, "verified": verified,
        "records": records, "checkpoints": checkpoints, "witnesses": kept_statements(dir, sub),
    }))
}

fn verify_in(dir: &Path, sub: &str, accept: fn(Kind) -> bool, pubkey: &str) -> Res<String> {
    entropa_nodecore::verify_ledger(dir, sub, accept, pubkey).map_err(|e| e.to_string())
}
