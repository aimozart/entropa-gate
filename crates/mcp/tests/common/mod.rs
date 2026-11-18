//! Shared fixtures. All data is synthetic: logs are built here with throwaway keys.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_core::transparency_log::{encode_record, Checkpoint, Receipt, TransparencyLog};
use entropa_core::Probe;
use entropa_mcp::{CallOutcome, LogSource, Server};
use serde_json::{json, Value};

pub const T0: u64 = 1_000_000;

/// A log of `n` v2 records `("event-<i>", Some("test"))`.
pub fn log_of(n: usize) -> TransparencyLog {
    let mut log = TransparencyLog::new();
    for i in 0..n {
        log.append(&encode_record(&format!("event-{i}"), Some("test")).unwrap());
    }
    log
}

/// In-memory source standing in for a file export.
pub struct MemSource {
    pub head: Checkpoint,
    pub records: Vec<Vec<u8>>,
}
impl LogSource for MemSource {
    fn kind(&self) -> &'static str {
        "file"
    }
    fn head(&self) -> Result<Checkpoint, String> {
        Ok(self.head.clone())
    }
    fn read(&self, since: usize, limit: usize) -> Result<Vec<(usize, Vec<u8>)>, String> {
        Ok(self
            .records
            .iter()
            .enumerate()
            .skip(since)
            .take(limit)
            .map(|(i, r)| (i, r.clone()))
            .collect())
    }
}

pub struct World {
    pub probe: Probe,
    pub log: TransparencyLog,
    pub head: Checkpoint,
}

pub fn world(n: usize) -> World {
    let probe = Probe::spawn();
    let log = log_of(n);
    let head = log.checkpoint(&probe, 1_700_000_000);
    World { probe, log, head }
}

impl World {
    pub fn receipt(&self, i: usize) -> Receipt {
        self.log.receipt(i, &self.head).unwrap()
    }
    pub fn mem_source(&self) -> MemSource {
        let records = (0..self.log.len())
            .map(|i| self.receipt(i).record)
            .collect();
        MemSource {
            head: self.head.clone(),
            records,
        }
    }
    /// Server trusting this world's key, with its log as the source.
    pub fn server(&self) -> Server {
        Server::new(
            vec![self.probe.pubkey_hex()],
            Some(Box::new(self.mem_source())),
        )
    }
    /// Server trusting this world's key, no log source.
    pub fn server_no_source(&self) -> Server {
        Server::new(vec![self.probe.pubkey_hex()], None)
    }
}

/// Call a tool; fails with the explicit red reason while the stub answers.
pub fn call(s: &mut Server, tool: &str, args: Value) -> CallOutcome {
    call_at(s, tool, args, T0)
}
pub fn call_at(s: &mut Server, tool: &str, args: Value, now_ms: u64) -> CallOutcome {
    let out = s.call_at(tool, &args, now_ms);
    assert!(!out.is_not_implemented(), "{tool}: not yet implemented");
    out
}

/// Assert a normal (non-error) result and return its body.
pub fn ok(out: CallOutcome) -> Value {
    assert!(
        !out.is_error,
        "expected a normal result, got error: {}",
        out.body
    );
    out.body
}
/// Assert a tool execution error with the given code.
pub fn err_code(out: CallOutcome, code: &str) -> Value {
    assert!(out.is_error, "expected isError, got result: {}", out.body);
    assert_eq!(out.body["error"], json!(code), "body: {}", out.body);
    out.body
}

pub fn cp_json(c: &Checkpoint) -> Value {
    serde_json::to_value(c).unwrap()
}
pub fn receipt_json(r: &Receipt) -> Value {
    serde_json::to_value(r).unwrap()
}
