//! # entropa-witnessd
//!
//! A checkpoint witness as a small service. The protocol and every check live in `entropa-witness`; this crate adds
//! the parts that need a machine: file-backed state with compare-and-swap, an HTTP interface, and configuration. It
//! fails closed, never echoes a request, and keeps no log content: only checkpoints (a root, a size, a time).

#[cfg(feature = "aws")]
pub mod s3;

use axum::extract::{DefaultBodyLimit, State as AxState};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use entropa_core::{CheckpointSigner, SignError};
use entropa_witness::{
    log_id_for, LogConfig, State, StateStore, StoreError, Witness, WitnessError,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_BODY: usize = 66 * 1024;
pub(crate) const MAX_EVIDENCE_LINES: usize = 100;

/// The logs this witness watches: `(public key hex, accept the first checkpoint on trust)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessConfig {
    /// Log public keys (lowercase hex) and their `allow_first` flag.
    pub logs: Vec<(String, bool)>,
}

/// A boxed signer usable wherever a concrete signer is expected.
struct BoxSigner(Box<dyn CheckpointSigner + Send + Sync>);

impl CheckpointSigner for BoxSigner {
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

/// State kept as one small file per log (`<log_id>.state`); the version tag is the hash of its content, so the
/// compare-and-swap detects any other writer. One service instance is expected; the in-process lock covers threads.
pub struct FileStateStore {
    dir: PathBuf,
    lock: Mutex<()>,
}

pub(crate) fn fail(m: &str) -> StoreError {
    StoreError::Failed(m.to_string())
}

pub(crate) fn check_id(log_id: &str) -> Result<(), StoreError> {
    if log_id.len() == 64
        && log_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(fail("bad log id"))
    }
}

impl FileStateStore {
    /// Open (and create) the state directory.
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|_| "cannot create the state directory".to_string())?;
        Ok(Self {
            dir: dir.to_path_buf(),
            lock: Mutex::new(()),
        })
    }

    fn read(&self, log_id: &str) -> Result<Option<(State, String)>, StoreError> {
        check_id(log_id)?;
        let p = self.dir.join(format!("{log_id}.state"));
        let text = match std::fs::read_to_string(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(fail("cannot read the state")),
        };
        let mut it = text.split_whitespace();
        let size: usize = it
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| fail("corrupt state"))?;
        let root_hex = it.next().ok_or_else(|| fail("corrupt state"))?;
        let mut root = [0u8; 32];
        let raw = hex::decode(root_hex).map_err(|_| fail("corrupt state"))?;
        if raw.len() != 32 {
            return Err(fail("corrupt state"));
        }
        root.copy_from_slice(&raw);
        Ok(Some((
            State { size, root },
            hex::encode(blake3::hash(text.as_bytes()).as_bytes()),
        )))
    }
}

impl StateStore for FileStateStore {
    fn get(&self, log_id: &str) -> Result<Option<(State, String)>, StoreError> {
        let _g = self.lock.lock().map_err(|_| fail("lock"))?;
        self.read(log_id)
    }

    fn compare_and_swap(
        &self,
        log_id: &str,
        expected: Option<&str>,
        new: &State,
    ) -> Result<(), StoreError> {
        let _g = self.lock.lock().map_err(|_| fail("lock"))?;
        let current = self.read(log_id)?.map(|(_, v)| v);
        if current.as_deref() != expected {
            return Err(StoreError::Conflict);
        }
        let p = self.dir.join(format!("{log_id}.state"));
        let tmp = self.dir.join(format!("{log_id}.tmp"));
        std::fs::write(&tmp, format!("{} {}\n", new.size, hex::encode(new.root)))
            .map_err(|_| fail("cannot write the state"))?;
        std::fs::rename(&tmp, &p).map_err(|_| fail("cannot replace the state"))
    }

    fn record_equivocation(&self, log_id: &str, evidence: &str) -> Result<(), StoreError> {
        check_id(log_id)?;
        let _g = self.lock.lock().map_err(|_| fail("lock"))?;
        let p = self.dir.join(format!("{log_id}.equivocation.log"));
        let n = std::fs::read_to_string(&p)
            .map(|t| t.lines().count())
            .unwrap_or(0);
        if n >= MAX_EVIDENCE_LINES {
            return Ok(()); // capped so a flood of bad proofs cannot grow the file without bound
        }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .map_err(|_| fail("cannot record evidence"))?;
        writeln!(f, "{}", evidence.replace(['\n', '\r'], " "))
            .map_err(|_| fail("cannot record evidence"))
    }
}

/// A boxed state store, so the HTTP layer is the same for files, S3 or anything else that implements the trait.
struct BoxStore(Box<dyn StateStore + Send + Sync>);

impl StateStore for BoxStore {
    fn get(&self, log_id: &str) -> Result<Option<(State, String)>, StoreError> {
        self.0.get(log_id)
    }
    fn compare_and_swap(
        &self,
        log_id: &str,
        expected: Option<&str>,
        new: &State,
    ) -> Result<(), StoreError> {
        self.0.compare_and_swap(log_id, expected, new)
    }
    fn record_equivocation(&self, log_id: &str, evidence: &str) -> Result<(), StoreError> {
        self.0.record_equivocation(log_id, evidence)
    }
}

type Shared = Arc<Witness<BoxStore, BoxSigner>>;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn status(e: &WitnessError) -> (StatusCode, &'static str) {
    match e {
        WitnessError::Invalid(_) | WitnessError::NotImplemented => {
            (StatusCode::BAD_REQUEST, "invalid request")
        }
        WitnessError::Limit(_) => (StatusCode::PAYLOAD_TOO_LARGE, "too large"),
        WitnessError::UnknownLog => (StatusCode::NOT_FOUND, "unknown log"),
        WitnessError::BadSignature => (StatusCode::FORBIDDEN, "bad signature"),
        WitnessError::FirstNotAllowed => (StatusCode::CONFLICT, "first checkpoint not accepted"),
        WitnessError::Rollback => (StatusCode::CONFLICT, "rollback"),
        WitnessError::Equivocation => (StatusCode::CONFLICT, "equivocation"),
        WitnessError::BadConsistency => (StatusCode::CONFLICT, "inconsistent"),
        WitnessError::StoreConflict => (StatusCode::SERVICE_UNAVAILABLE, "retry"),
        WitnessError::Store(_) | WitnessError::Sign(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

async fn cosign(AxState(w): AxState<Shared>, body: String) -> (StatusCode, String) {
    match tokio::task::spawn_blocking(move || w.cosign(&body, now())).await {
        Ok(Ok(statement)) => (StatusCode::OK, statement),
        Ok(Err(e)) => {
            let (c, m) = status(&e);
            (c, format!("{{\"error\":\"{m}\"}}"))
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"error\":\"internal\"}".to_string(),
        ),
    }
}

async fn pubkey(AxState(w): AxState<Shared>) -> String {
    w.pubkey_hex()
}

/// Build the HTTP application: `POST /v1/cosign`, `GET /v1/pubkey`, `GET /healthz`.
pub fn app<S>(
    cfg: WitnessConfig,
    store: S,
    signer: Box<dyn CheckpointSigner + Send + Sync>,
) -> Result<Router, String>
where
    S: StateStore + Send + Sync + 'static,
{
    let logs = cfg
        .logs
        .into_iter()
        .map(|(pubkey_hex, allow_first)| LogConfig {
            log_id: log_id_for(&pubkey_hex),
            pubkey_hex,
            allow_first,
        })
        .collect();
    let w = Witness::new(logs, BoxStore(Box::new(store)), BoxSigner(signer))
        .map_err(|e| format!("bad configuration: {e:?}"))?;
    Ok(Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/pubkey", get(pubkey))
        .route("/v1/cosign", post(cosign))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(Arc::new(w)))
}
