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

/// The three ledgers of a node; each signs with its own key (KEYS1, a stage record (not published)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ledger {
    /// The AI-decision ledger.
    Decisions,
    /// The evidence ledger.
    Evidence,
    /// The council ledger (its key is optional).
    Council,
}

impl Ledger {
    /// All ledgers, in report order.
    pub const ALL: [Ledger; 3] = [Ledger::Decisions, Ledger::Evidence, Ledger::Council];

    /// Parse the command-line name.
    pub fn parse(s: &str) -> Option<Ledger> {
        match s {
            "decisions" => Some(Ledger::Decisions),
            "evidence" => Some(Ledger::Evidence),
            "council" => Some(Ledger::Council),
            _ => None,
        }
    }

    /// The command-line name.
    pub fn name(self) -> &'static str {
        match self {
            Ledger::Decisions => "decisions",
            Ledger::Evidence => "evidence",
            Ledger::Council => "council",
        }
    }

    fn file(self) -> &'static str {
        match self {
            Ledger::Decisions => "decisions.key",
            Ledger::Evidence => "evidence.key",
            Ledger::Council => "council.key",
        }
    }

    fn env(self) -> &'static str {
        match self {
            Ledger::Decisions => "PLATINUM_KEY_FILE_DECISIONS",
            Ledger::Evidence => "PLATINUM_KEY_FILE_EVIDENCE",
            Ledger::Council => "PLATINUM_KEY_FILE_COUNCIL",
        }
    }
}

/// Where a ledger's key came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// The ledger's own key (file in the node directory, or `PLATINUM_KEY_FILE_<LEDGER>`).
    Own,
    /// The legacy key shared by the ledgers (`platinum.key` or `PLATINUM_KEY_FILE`): a migration state.
    LegacyShared,
}

fn legacy_path(dir: &Path) -> PathBuf {
    dir.join("platinum.key")
}

/// The key file for `ledger` and its source: its own env override, its own file, the legacy env override, the legacy file.
fn key_location(dir: &Path, ledger: Ledger) -> Option<(PathBuf, KeySource, bool)> {
    if let Some(p) = std::env::var_os(ledger.env()).map(PathBuf::from) {
        return Some((p, KeySource::Own, true));
    }
    let own = dir.join(ledger.file());
    if own.exists() {
        return Some((own, KeySource::Own, false));
    }
    if let Some(p) = std::env::var_os("PLATINUM_KEY_FILE").map(PathBuf::from) {
        return Some((p, KeySource::LegacyShared, true));
    }
    let legacy = legacy_path(dir);
    legacy
        .exists()
        .then_some((legacy, KeySource::LegacyShared, false))
}

fn read_probe(path: &Path, external: bool) -> Res<Probe> {
    let meta = std::fs::metadata(path).map_err(|_| "no key file (run init first)".to_string())?;
    // an external path points at a mounted secret (a managed secret store sets its own permissions)
    if !external && meta.permissions().mode() & 0o077 != 0 {
        return fail("the key file must not be readable by group or others (chmod 600)");
    }
    let seed = std::fs::read_to_string(path).map_err(|_| "cannot read the key file".to_string())?;
    Probe::from_signing_key_hex(seed.trim())
        .ok_or_else(|| "the key file is not a valid key".to_string())
}

/// Load the signing key of `ledger` and where it came from.
pub fn load_probe_for(dir: &Path, ledger: Ledger) -> Res<(Probe, KeySource)> {
    let (p, src, ext) =
        key_location(dir, ledger).ok_or_else(|| "no key file (run init first)".to_string())?;
    Ok((read_probe(&p, ext)?, src))
}

/// Load the AI-decision ledger's signing key (kept for callers that name no ledger).
pub fn load_probe(dir: &Path) -> Res<Probe> {
    Ok(load_probe_for(dir, Ledger::Decisions)?.0)
}

/// The signer of one ledger: a Google Cloud KMS ML-DSA-65 key when `ENTROPA_GCP_KMS_KEY` names one (one key for all
/// ledgers, a limit of KEYS1), otherwise the ledger's own key, otherwise the legacy shared key.
pub fn node_signer_for(dir: &Path, ledger: Ledger) -> Res<Box<dyn CheckpointSigner>> {
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
    Ok(Box::new(load_probe_for(dir, ledger)?.0))
}

/// The AI-decision ledger's signer (the node's default; see [`node_signer_for`]).
pub fn node_signer(dir: &Path) -> Res<Box<dyn CheckpointSigner>> {
    node_signer_for(dir, Ledger::Decisions)
}

fn write_new_key(path: &Path) -> Res<()> {
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|_| "no random source".to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "cannot create the key file (it may already exist)".to_string())?;
    std::io::Write::write_all(&mut f, format!("{}\n", hex::encode(seed)).as_bytes())
        .map_err(|_| "cannot write the key file".to_string())
}

/// Create the optional or a missing key of one ledger (never overwrites an existing file).
pub fn keys_add(dir: &Path, ledger: Ledger) -> Res<()> {
    std::fs::create_dir_all(dir).map_err(|_| "cannot create the directory".to_string())?;
    write_new_key(&dir.join(ledger.file()))
}

/// One line per ledger that has a key: `<ledger> source=own|legacy_shared key_id=<id>` (the council line only when it has
/// its own key). Fails when two ledgers with OWN keys share a key, and (unless `allow_legacy`) when any ledger uses the
/// legacy shared key. No key material is ever printed.
pub fn keys_check(dir: &Path, allow_legacy: bool) -> Res<String> {
    let mut lines = Vec::new();
    let mut own_ids: Vec<(Ledger, String)> = Vec::new();
    let mut legacy = false;
    for l in Ledger::ALL {
        let Some((_, src, _)) = key_location(dir, l) else {
            continue;
        };
        if l == Ledger::Council && src == KeySource::LegacyShared {
            continue;
        }
        let (probe, _) = load_probe_for(dir, l)?;
        let id = entropa_approvals::key_id(&probe.pubkey_hex());
        let tag = match src {
            KeySource::Own => "own",
            KeySource::LegacyShared => "legacy_shared",
        };
        if src == KeySource::Own {
            if let Some((o, _)) = own_ids.iter().find(|(_, i)| *i == id) {
                return Err(format!("{} and {} share one key", o.name(), l.name()));
            }
            own_ids.push((l, id.clone()));
        } else {
            legacy = true;
        }
        lines.push(format!("{} source={tag} key_id={id}", l.name()));
    }
    let text = lines.join("\n");
    if legacy && !allow_legacy {
        return Err(format!(
            "{text}\nlegacy_shared key in use (migration needed, see docs/KEYS1-MIGRATION.md)"
        ));
    }
    Ok(text)
}

/// Create the AI-decision and evidence keys (mode 0600, distinct) and the ledger directory. The council key is optional
/// ([`keys_add`]).
pub fn init(dir: &Path) -> Res<()> {
    std::fs::create_dir_all(dir).map_err(|_| "cannot create the directory".to_string())?;
    if Ledger::ALL.iter().any(|l| dir.join(l.file()).exists()) || legacy_path(dir).exists() {
        return fail("already initialised");
    }
    write_new_key(&dir.join(Ledger::Decisions.file()))?;
    write_new_key(&dir.join(Ledger::Evidence.file()))?;
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
    log_with(dir, &*node_signer_for(dir, Ledger::Decisions)?, request)
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
    log_evidence_with(dir, &*node_signer_for(dir, Ledger::Evidence)?, request)
}

/// Re-read every record and checkpoint and check every signature; returns an `OK records=N checkpoints=M` line.
pub fn verify(dir: &Path) -> Res<String> {
    verify_with(dir, &node_signer_for(dir, Ledger::Decisions)?.pubkey_hex())
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
    log_council_with(dir, &*node_signer_for(dir, Ledger::Council)?, request)
}

/// Verify the council ledger.
pub fn verify_council(dir: &Path) -> Res<String> {
    verify_council_with(dir, &node_signer_for(dir, Ledger::Council)?.pubkey_hex())
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
    export_in(dir, "council-ledger", Ledger::Council, verify_council(dir)?)
}

/// Verify the evidence ledger (kinds: pipeline run, control check, access, change, policy).
pub fn verify_evidence(dir: &Path) -> Res<String> {
    verify_evidence_with(dir, &node_signer_for(dir, Ledger::Evidence)?.pubkey_hex())
}

/// Verify the evidence ledger under an explicit public key.
pub fn verify_evidence_with(dir: &Path, pubkey_hex: &str) -> Res<String> {
    verify_in(dir, "evidence-ledger", Kind::is_evidence, pubkey_hex)
}

/// Export the evidence ledger as a public, data-minimal bundle: every record's codes, counts and hashes, the
/// signed checkpoints and the public key. The ledger is verified first; a failed verification is an error.
pub fn export_evidence(dir: &Path) -> Res<Value> {
    export_in(
        dir,
        "evidence-ledger",
        Ledger::Evidence,
        verify_evidence(dir)?,
    )
}

/// Export the AI-decision ledger the same way (codes, model metadata, hashes, plain English; no text).
pub fn export_decisions(dir: &Path) -> Res<Value> {
    export_in(dir, "ledger", Ledger::Decisions, verify(dir)?)
}

fn export_in(dir: &Path, sub: &str, ledger: Ledger, verified: String) -> Res<Value> {
    let pubkey = node_signer_for(dir, ledger)?.pubkey_hex();
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
