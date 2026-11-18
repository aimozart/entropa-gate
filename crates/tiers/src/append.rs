//! LEDGER-INCREMENTAL (a stage record (not published)): `IncrementalLedger` appends to the evidence-ledger files (`records.log`, `checkpoints.log`, the format `entropa_ledger::FileStore`
//! reads and the unchanged verifier checks) without replaying them: it keeps the Merkle frontier and the file lengths between writes. The checkpoint is signed BEFORE any byte is written;
//! a kill between the record line and the checkpoint line is repaired at the next write; a persistent OS lock (released when a process dies) serialises writers.

use entropa_core::transparency_log::{encode_record, Checkpoint, TransparencyLog};
use entropa_core::{CheckpointSigner, SignError};
use entropa_ledger::{encode_event, sign_event, EventFields};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Test hooks: stop at a chosen point of a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failpoint {
    /// Return an error after the record line is written and before the checkpoint line.
    AfterRecord,
    /// Abort the process after the record line is written and before the checkpoint line.
    AbortAfterRecord,
}

/// A borrowed signer behind a trait object, usable where a sized signer is expected.
pub(crate) struct Dyn<'a>(pub(crate) &'a dyn CheckpointSigner);
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

struct State {
    tlog: TransparencyLog,
    rec_len: u64,
    cp_len: u64,
}

/// An append-only writer for `DIR/evidence-ledger` that keeps the Merkle frontier between writes.
pub struct IncrementalLedger {
    dir: PathBuf,
    signer: Box<dyn CheckpointSigner>,
    failpoint: Option<Failpoint>,
    lock_timeout: Duration,
    state: Mutex<Option<State>>,
}

fn io(what: &str, e: std::io::Error) -> String {
    format!("{what}: {:?}", e.kind())
}

impl IncrementalLedger {
    /// A writer for the evidence ledger of the node directory `dir`, signing checkpoints with `signer`.
    pub fn new(dir: PathBuf, signer: Box<dyn CheckpointSigner>) -> Self {
        IncrementalLedger {
            dir,
            signer,
            failpoint: None,
            lock_timeout: Duration::from_secs(20),
            state: Mutex::new(None),
        }
    }
    /// The same writer waiting at most `t` for the writer lock (default 20 s).
    pub fn with_lock_timeout(mut self, t: Duration) -> Self {
        self.lock_timeout = t;
        self
    }
    /// The same writer with a failpoint set.
    pub fn with_failpoint(mut self, f: Failpoint) -> Self {
        self.failpoint = Some(f);
        self
    }
    fn ledger_dir(&self) -> PathBuf {
        self.dir.join("evidence-ledger")
    }

    fn lock(&self) -> Result<std::fs::File, String> {
        let d = self.ledger_dir();
        std::fs::create_dir_all(&d).map_err(|e| io("create dir", e))?;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(d.join(".append.lock"))
            .map_err(|e| io("lock file", e))?;
        let start = Instant::now();
        loop {
            match f.try_lock() {
                Ok(()) => break,
                Err(_) if start.elapsed() < self.lock_timeout => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(_) => return Err("the ledger is locked by another writer".into()),
            }
        }
        // a FileStore `.lock` means a verifier or the node has the store open: wait a little, then refuse
        let start = Instant::now();
        while d.join(".lock").exists() {
            if start.elapsed() > Duration::from_millis(500) {
                return Err("the store is open elsewhere (a .lock file exists)".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(f)
    }

    fn lens(&self) -> (u64, u64) {
        let d = self.ledger_dir();
        let l = |n: &str| std::fs::metadata(d.join(n)).map_or(0, |m| m.len());
        (l("records.log"), l("checkpoints.log"))
    }

    /// Read both files into a fresh state; repair a missing last checkpoint.
    fn rebuild(&self) -> Result<(State, bool), String> {
        let d = self.ledger_dir();
        let read = |n: &str| -> Result<String, String> {
            match std::fs::read_to_string(d.join(n)) {
                Ok(t) if !t.is_empty() && !t.ends_with('\n') => Err(format!(
                    "{n} ends with a partial line: a person must look at it"
                )),
                Ok(t) => Ok(t),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
                Err(e) => Err(io(n, e)),
            }
        };
        let (rec_text, cp_text) = (read("records.log")?, read("checkpoints.log")?);
        let mut tlog = TransparencyLog::new();
        for line in rec_text.lines() {
            let bytes = hex::decode(line).map_err(|_| "a record line is not hex".to_string())?;
            tlog.append(&bytes);
        }
        let last: Option<Checkpoint> = match cp_text.lines().last() {
            Some(l) => Some(
                serde_json::from_str(l)
                    .map_err(|_| "a checkpoint line is not valid".to_string())?,
            ),
            None => None,
        };
        let covered = last.as_ref().map_or(0, |c| c.size);
        if covered > tlog.len() {
            return Err("the last checkpoint covers more records than exist".into());
        }
        let (rec_len, mut cp_len) = self.lens();
        let repaired = tlog.len() > covered;
        if repaired {
            // a kill left records without a checkpoint: sign one over the current tree before anything else
            let cp = tlog
                .checkpoint_with(
                    &Dyn(self.signer.as_ref()),
                    last.as_ref().map_or(0, |c| c.timestamp),
                )
                .map_err(|e| e.to_string())?;
            let line =
                serde_json::to_string(&cp).map_err(|_| "checkpoint not encodable".to_string())?;
            self.write_line("checkpoints.log", &line)?;
            cp_len = self.lens().1;
        }
        Ok((
            State {
                tlog,
                rec_len,
                cp_len,
            },
            repaired,
        ))
    }

    fn write_line(&self, file: &str, line: &str) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.ledger_dir().join(file))
            .map_err(|e| io(file, e))?;
        f.write_all(format!("{line}\n").as_bytes())
            .map_err(|e| io(file, e))?;
        f.sync_data().map_err(|e| io(file, e))
    }

    /// Make a ledger that a kill left with a record but no checkpoint verifiable again, WITHOUT appending anything: signs and appends a checkpoint over the current tree. `Ok(true)` when it repaired.
    pub fn repair(&self) -> Result<bool, String> {
        let _lock = self.lock()?;
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (st, repaired) = self.rebuild()?;
        *guard = Some(st);
        Ok(repaired)
    }

    /// Sign and append one event (record line, then checkpoint line). Returns the index of the record.
    pub fn append_event(&self, fields: &EventFields) -> Result<usize, String> {
        let _lock = self.lock()?;
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now_lens = self.lens();
        let fresh = match guard.as_ref() {
            Some(s) => (s.rec_len, s.cp_len) == now_lens,
            None => false,
        };
        if !fresh {
            *guard = None;
            *guard = Some(self.rebuild()?.0);
        }
        let st = guard.as_mut().ok_or("no state")?;
        let signed =
            sign_event(&Dyn(self.signer.as_ref()), fields).map_err(|e| format!("{e:?}"))?;
        let payload = encode_event(&signed).map_err(|e| format!("{e:?}"))?;
        let record = encode_record(&payload, Some(fields.kind.as_str()))
            .map_err(|_| "record too large".to_string())?;
        // sign the new checkpoint BEFORE anything is written; a failure leaves the files untouched and the in-memory tree is dropped
        let index = st.tlog.append(&record);
        let cp = match st
            .tlog
            .checkpoint_with(&Dyn(self.signer.as_ref()), fields.ts)
        {
            Ok(cp) => cp,
            Err(e) => {
                *guard = None;
                return Err(e.to_string());
            }
        };
        let cp_line =
            serde_json::to_string(&cp).map_err(|_| "checkpoint not encodable".to_string())?;
        if let Err(e) = self.write_line("records.log", &hex::encode(&record)) {
            *guard = None;
            return Err(e);
        }
        match self.failpoint {
            Some(Failpoint::AfterRecord) => {
                *guard = None;
                return Err("failpoint: after the record line".into());
            }
            Some(Failpoint::AbortAfterRecord) => std::process::abort(),
            None => {}
        }
        if let Err(e) = self.write_line("checkpoints.log", &cp_line) {
            *guard = None;
            return Err(e);
        }
        let (rl, cl) = self.lens();
        if let Some(s) = guard.as_mut() {
            s.rec_len = rl;
            s.cp_len = cl;
        }
        Ok(index)
    }

    /// The number of records in the ledger on disk.
    pub fn len(&self) -> Result<usize, String> {
        let text = match std::fs::read_to_string(self.ledger_dir().join("records.log")) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(io("records.log", e)),
        };
        Ok(text.lines().count())
    }
    /// True when the ledger holds no record.
    pub fn is_empty(&self) -> Result<bool, String> {
        self.len().map(|n| n == 0)
    }
}
