//! Hash-only records, offline verification and status, on the client's own ledger (`<dir>/ledger`). The request schema is the one of
//! `entropa-platinum log` (closed codes, text fields hashed and dropped), so a ledger written here verifies with that tool and the other way round.
use crate::keys::load;
use crate::{GateError, Res};
use entropa_ledger::{FileStore, Kind, LedgerStore};
use entropa_nodecore::{append, decision_fields, verify_ledger, NodeError, StoreStage};
use std::path::Path;

/// The largest request `record` reads (bytes).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// What `record` returns.
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

impl Receipt {
    /// The receipt as one line of JSON.
    pub fn to_json(&self) -> String {
        serde_json::json!({"index": self.index, "subject_hash": self.subject_hash, "size": self.size, "root": self.root}).to_string()
    }
}

/// What `status` returns (no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Number of records.
    pub records: u64,
    /// Number of checkpoints.
    pub checkpoints: u64,
    /// The public key (hex), safe to share.
    pub pubkey: String,
    /// The short key id.
    pub key_id: String,
}

fn invalid<T>(m: &str) -> Res<T> {
    Err(GateError::Invalid(m.to_string()))
}
fn map(e: NodeError) -> GateError {
    match e {
        NodeError::Invalid(m) => GateError::Invalid(m),
        NodeError::Io(m) => GateError::Io(m),
        NodeError::Verify(m) => GateError::Verify(m),
        NodeError::Store(StoreStage::Open, _) => GateError::Io("the ledger does not open".into()),
        NodeError::Store(StoreStage::Append, _) => GateError::Io("cannot append".into()),
        NodeError::Store(StoreStage::Checkpoint, _) => {
            GateError::Io("cannot write the checkpoint".into())
        }
    }
}

/// Append one hash-only record (one JSON request) with a signed checkpoint.
pub fn record(dir: &Path, request: &str) -> Res<Receipt> {
    if request.len() > MAX_REQUEST_BYTES {
        return invalid("request: too large");
    }
    let probe = load(dir)?;
    let fields = decision_fields(request, &probe.pubkey_hex()).map_err(map)?;
    let r = append(dir, "ledger", &probe, &fields).map_err(map)?;
    Ok(Receipt {
        index: r.index,
        subject_hash: r.subject_hash,
        size: r.size,
        root: r.root,
    })
}

/// Re-read every record and checkpoint and check every signature; returns an `OK records=N checkpoints=M` line.
pub fn verify(dir: &Path) -> Res<String> {
    let pubkey = load(dir)?.pubkey_hex();
    verify_ledger(dir, "ledger", |k| k == Kind::PlatinumDecision, &pubkey).map_err(|e| match e {
        NodeError::Store(StoreStage::Open, _) => {
            GateError::Verify("the ledger does not match its checkpoints or is malformed".into())
        }
        other => map(other),
    })
}

/// Counts and the public key.
pub fn status(dir: &Path) -> Res<Status> {
    let probe = load(dir)?;
    let store = FileStore::open(&dir.join("ledger"))
        .map_err(|_| GateError::Io("the ledger does not open".into()))?;
    let pubkey = probe.pubkey_hex();
    Ok(Status {
        records: store.len() as u64,
        checkpoints: store.checkpoints().len() as u64,
        key_id: entropa_approvals::key_id(&pubkey),
        pubkey,
    })
}
