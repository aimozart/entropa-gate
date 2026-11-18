//! # entropa-policy
//!
//! A Cedar policy gate combined with the approvals gate, specified in
//! `docs/ARCHITECTURE-CEDAR.md`: the approvals result is placed in the Cedar context, Cedar decides,
//! and a code guard keeps hard-rule classes owner-only whatever the policy text says. Any Cedar
//! evaluation error fails closed. Decisions can be written to the log as signed, data-minimal
//! records.

use entropa_approvals::{ActionClass, BlockReason};

mod engine;
mod record;

pub use engine::Engine;
pub use record::{
    append_record, decode_record, record_canonical_bytes, record_digest, sign_record,
};

/// The marker the S4b stubs answered with. Kept so the S4b test helpers still compile; the
/// finished crate never produces it.
pub const NOT_IMPLEMENTED: &str = "not yet implemented";

/// Errors loading policies or building records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Never produced by the finished crate (kept for the S4b test helpers).
    NotImplemented,
    /// Schema or policy text does not parse.
    Parse(String),
    /// A policy does not validate against the schema.
    Validation(String),
    /// A size or count limit was exceeded.
    Limit(String),
    /// A record or request is malformed.
    Invalid(String),
}

/// What a request asks to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// One of the eight approval classes.
    Class(ActionClass),
    /// Reading the log.
    ReadLog,
    /// Appending a record.
    AppendRecord,
    /// Calling a tool.
    CallTool,
}

impl Action {
    /// Wire name (the Cedar action id).
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Class(c) => c.as_str(),
            Action::ReadLog => "read_log",
            Action::AppendRecord => "append_record",
            Action::CallTool => "call_tool",
        }
    }
    /// Parse a wire name.
    pub fn parse(s: &str) -> Option<Action> {
        match s {
            "read_log" => Some(Action::ReadLog),
            "append_record" => Some(Action::AppendRecord),
            "call_tool" => Some(Action::CallTool),
            other => ActionClass::parse(other).map(Action::Class),
        }
    }
    /// Whether the combination requires approval evidence for this action.
    pub fn is_guarded(self) -> bool {
        matches!(self, Action::Class(_))
    }
}

/// The principal's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleName {
    /// A person.
    Human,
    /// An AI agent.
    Ai,
    /// A service.
    Service,
}

/// Deployment environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Env {
    /// Development.
    Dev,
    /// Production.
    Prod,
}

/// One authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Principal key id (16 hex).
    pub principal: String,
    /// Principal role.
    pub role: RoleName,
    /// Whether the principal holds a signing key.
    pub has_key: bool,
    /// The action.
    pub action: Action,
    /// Subject hash (64 hex).
    pub subject_hash: String,
    /// Kind of subject (short token).
    pub subject_kind: String,
    /// Unix seconds.
    pub now: u64,
    /// Environment.
    pub env: Env,
}

/// Allow or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Allowed.
    Allow,
    /// Denied.
    Deny,
}

/// Why the final outcome is what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Never produced by the finished crate (kept for the S4b test helpers).
    NotImplemented,
    /// Allowed by policy and, where needed, by evidence.
    Allowed,
    /// Cedar denied (default deny or a forbid).
    CedarDeny,
    /// A policy errored during evaluation: fail closed.
    PolicyError,
    /// The approvals gate blocked.
    GateBlocked(BlockReason),
    /// An attestation was the only approval, and it does not count here.
    AttestationNotAccepted,
    /// The request could not be built safely.
    InvalidRequest,
}

/// Observe computes and records but does not enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The decision must be acted on.
    Enforce,
    /// The decision is recorded only (the analogue of AgentCore's LOG_ONLY).
    Observe,
}

/// The decision with its evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The final outcome.
    pub outcome: Outcome,
    /// What Cedar said on its own (`None` when it was not consulted or errored).
    pub cedar: Option<Outcome>,
    /// Ids of the determining policies.
    pub determining: Vec<String>,
    /// Ids of policies that errored.
    pub error_policies: Vec<String>,
    /// Why.
    pub reason: Reason,
    /// False in observe mode.
    pub enforced: bool,
    /// Approval state placed in the Cedar context.
    pub approval_state: String,
    /// Whether the approval in the context was an attestation.
    pub approval_attested: bool,
}

/// A signed, data-minimal decision record (doc section 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRecord {
    /// Canonical JSON payload including `sig`.
    pub payload: String,
}
