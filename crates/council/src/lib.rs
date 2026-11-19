//! # entropa-council
//!
//! The pure, deterministic core of the Decision Review Council (`the council design notes`): closed-code
//! events with a strict decoder and signatures, the session state machine and quorum rule, critic-reliability
//! scoring, the planted-fault evaluation harness, retrieval provenance and the replay harness. It uses no model,
//! no network, no clock and no file; time is an argument.

mod canon;
mod carryover;
mod event;
mod memory;
mod memory_eval;
mod planted;
mod provenance;
mod reliability;
mod render;
mod replay;
mod schema;
mod session;

pub use carryover::{plan_carryover, Candidate, Carryover};
pub use event::{
    canonical_bytes, decode_event, event_digest, sign_event, verify_event, verify_event_with,
    Event, Registry, SignatureVerifier,
};
pub use memory::{
    manifest_hash, memory_hash, precedent_terms, LexHit, LexicalConfig, LexicalIndex, Precedent,
};
pub use memory_eval::{
    evaluate_retrieval, planted_retrieval_suite, PlantedSuite, RetrievalCase, RetrievalReport,
    RetrievalThresholds,
};
pub use planted::{evaluate, Case, CaseKind, Finding, Output, Report, Suite, Thresholds};
pub use provenance::{admit, precedent_reference, Entry, Hit, Index, ModelDescriptor};
pub use reliability::{Reliability, Score, Verdict};
pub use render::render_for_model;
pub use replay::{input_hash, replay, Decider, ReplayItem, ReplayReport, Verdict as ReplayVerdict};
pub use session::{
    findings_hash, window_hash, ApprovedChange, Quorum, Scope, Session, SessionState,
};

/// Why an operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CouncilError {
    /// The input is malformed or breaks the closed-code schema.
    Invalid(String),
    /// A signature did not verify.
    Verify(String),
    /// Signing failed.
    Sign(String),
    /// The event was signed by a role that may not write this event type.
    WrongRole,
    /// The event does not fit the current state of the session.
    OutOfOrder,
    /// The event belongs to another session.
    WrongSession,
    /// The same finding, rebuttal or decision was submitted twice.
    Duplicate,
    /// The session has expired.
    Expired,
    /// The independence rule is broken (same family as the reviewed decision, or critic and contestor alike).
    Independence,
    /// An attested decision was offered for a hard-rule item.
    AttestationNotAccepted,
    /// A change was decided without an approval reference.
    MissingApproval,
    /// The window hash does not match the scope.
    WindowMismatch,
    /// The packet or report is incomplete or does not match what was submitted.
    Incomplete,
    /// A size or count limit was exceeded.
    Limit(String),
    /// A replay input does not match its recorded hash.
    HashMismatch(String),
}

/// The roles that sign council events (the council design notes section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// `scheduler`: opens and closes sessions, records proofs and evaluations.
    Scheduler,
    /// `critic-agent`.
    Critic,
    /// `contestor-agent`.
    Contestor,
    /// `orchestrator-agent`.
    Orchestrator,
    /// `human-principal`.
    Human,
    /// `builder-agent`.
    Builder,
    /// `generator`: records synthetic outcomes.
    Generator,
    /// A deciding agent (records which precedents it consulted).
    Agent,
}

/// The model provider recorded in an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    /// Amazon Bedrock (Nova).
    Bedrock,
    /// Google Vertex AI (Gemini).
    Vertex,
    /// The fake backend of tests and demos.
    Fake,
}

/// A model family, for the independence rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// Amazon Nova.
    Nova,
    /// Google Gemini.
    Gemini,
    /// The fake backend (exempt from the rule: it exists only in tests and demos).
    Fake,
}

impl Provider {
    /// Parse `bedrock`, `vertex` or `fake`.
    pub fn parse(s: &str) -> Option<Provider> {
        match s {
            "bedrock" => Some(Provider::Bedrock),
            "vertex" => Some(Provider::Vertex),
            "fake" => Some(Provider::Fake),
            _ => None,
        }
    }
    /// The family of this provider.
    pub fn family(self) -> Family {
        match self {
            Provider::Bedrock => Family::Nova,
            Provider::Vertex => Family::Gemini,
            Provider::Fake => Family::Fake,
        }
    }
}

/// True if a reviewer of family `reviewer` may review a decision of family `subject` (they must differ; `Fake` is exempt).
pub fn independent(reviewer: Family, subject: Family) -> bool {
    // (X, Fake) is covered by `reviewer != subject`; only a Fake reviewer needs its own clause
    reviewer == Family::Fake || reviewer != subject
}

/// The role that must sign an event of type `event_type` (for example `finding.submitted` -> `Critic`).
pub fn required_role(event_type: &str) -> Option<Role> {
    Some(match event_type {
        "session.opened"
        | "session.closed"
        | "session.expired"
        | "proof.recorded"
        | "evaluation.recorded"
        | "index.built" => Role::Scheduler,
        "finding.submitted" | "report.submitted" => Role::Critic,
        "rebuttal.submitted" => Role::Contestor,
        "packet.compiled" | "carryover.recorded" => Role::Orchestrator,
        "decision.recorded" | "precedent.revoked" => Role::Human,
        "change.linked" => Role::Builder,
        "outcome.recorded" => Role::Generator,
        "precedent.referenced" => Role::Agent,
        _ => return None,
    })
}
