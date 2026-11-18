//! Hash-only evidence records and the sink that writes them. A record carries closed codes, counts and a detail string that the node hashes
//! and drops; it never carries clause text or query text.

use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// One evidence request, in the shape `entropa-platinum log-evidence` accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceRequest {
    /// Event kind, for example `evidence.change`.
    pub kind: String,
    /// Closed label, for example `corpus_version`.
    pub label: String,
    /// `allow`, `deny`, `hold`, `escalate`, `release` or `info`.
    pub decision: String,
    /// Closed reason code.
    pub reason: String,
    /// Closed control code.
    pub control: String,
    /// Total count.
    pub total: u64,
    /// Passed count.
    pub passed: u64,
    /// Flagged count.
    pub flagged: u64,
    /// Detail text (hashed and dropped by the node): hashes and ids only.
    pub detail: String,
    /// Run id (unique per record).
    pub run_id: String,
}

/// Where records go.
pub trait RecordSink {
    /// Write one record; an error means the receipt was NOT written.
    fn emit(&self, r: &EvidenceRequest) -> Result<(), String>;
}

/// Writes records by running the `entropa-platinum` CLI against a local node directory. The server links no HTTP client; the node binary does
/// the signing.
pub struct ProcessSink {
    /// Path of the `entropa-platinum` binary.
    pub platinum_bin: PathBuf,
    /// The local scratch node directory.
    pub node_dir: PathBuf,
}

impl RecordSink for ProcessSink {
    fn emit(&self, r: &EvidenceRequest) -> Result<(), String> {
        let body = serde_json::to_string(r).map_err(|_| "cannot encode the record".to_string())?;
        let mut child = Command::new(&self.platinum_bin)
            .arg("log-evidence")
            .arg(&self.node_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "cannot start the node binary".to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(body.as_bytes())
                .map_err(|_| "cannot write to the node binary".to_string())?;
        }
        let out = child
            .wait_with_output()
            .map_err(|_| "the node binary did not finish".to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "the node refused the record: {}",
                String::from_utf8_lossy(&out.stderr)
                    .chars()
                    .take(200)
                    .collect::<String>()
                    .trim()
            ))
        }
    }
}

/// Discards every record. For evaluation harnesses and tests only: the MCP server refuses to start without a real sink.
pub struct NullSink;

impl RecordSink for NullSink {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        Ok(())
    }
}
