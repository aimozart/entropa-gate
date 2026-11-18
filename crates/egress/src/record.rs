//! Hash-only evidence records and the sink that receives them. The shape matches `entropa-standards::records` on purpose; the crate defines
//! its own copy so that it links no network-capable crate (invariant E4). An adapter to the platinum writer is stage EG3.
use serde::Serialize;

/// One evidence request: closed codes, counts and ids. Never request text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceRequest {
    /// Event kind.
    pub kind: String,
    /// Closed label: `egress_allowed`, `egress_redacted`, `egress_blocked` or `egress_policy_changed`.
    pub label: String,
    /// `allow` or `deny`.
    pub decision: String,
    /// Closed reason code.
    pub reason: String,
    /// Control code.
    pub control: String,
    /// Leaves scanned.
    pub total: u64,
    /// Leaves with no match.
    pub passed: u64,
    /// Leaves with a match.
    pub flagged: u64,
    /// Hashes, ids and counts only.
    pub detail: String,
    /// Unique per distinct decision.
    pub run_id: String,
}

/// Where records go. An error means the record was NOT written, and the decision becomes a block.
pub trait RecordSink {
    /// Write one record.
    fn emit(&self, r: &EvidenceRequest) -> Result<(), String>;
}
