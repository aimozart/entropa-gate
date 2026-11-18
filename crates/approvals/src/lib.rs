//! # entropa-approvals
//!
//! Signed approval records and a human gate over the Entropa log, specified in
//! `docs/ARCHITECTURE-APPROVALS.md`: data-minimal events (request, approve, deny, consume) signed
//! with ML-DSA-65, an actor directory, a deterministic replay with the validity rules, and a pure
//! gate. The ledger records approvals; it is never the authority for hard-rule actions until
//! The owner holds a key.

use std::collections::BTreeMap;

mod codec;
mod directory;
mod replay;

pub use codec::{append_event, canonical_bytes, decode, encode, key_id, sign, signing_digest};
pub use replay::{check, replay};

/// The marker the S3b stubs answered with. Kept so the S3b test helpers still compile; the
/// finished crate never produces it.
pub const NOT_IMPLEMENTED: &str = "not yet implemented";

/// What kind of action needs a human decision (fixed vocabulary, doc section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionClass {
    /// Deleting anything.
    Delete,
    /// Spending money.
    Spend,
    /// Publishing (crates.io, GitHub, ...).
    Publish,
    /// Merging into a protected branch.
    Merge,
    /// Deploying.
    Deploy,
    /// A choice of direction.
    Direction,
    /// Changing a policy file.
    PolicyChange,
    /// Changing credentials or permissions.
    CredentialsChange,
}

impl ActionClass {
    /// All classes.
    pub const ALL: [ActionClass; 8] = [
        ActionClass::Delete,
        ActionClass::Spend,
        ActionClass::Publish,
        ActionClass::Merge,
        ActionClass::Deploy,
        ActionClass::Direction,
        ActionClass::PolicyChange,
        ActionClass::CredentialsChange,
    ];
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ActionClass::Delete => "delete",
            ActionClass::Spend => "spend",
            ActionClass::Publish => "publish",
            ActionClass::Merge => "merge",
            ActionClass::Deploy => "deploy",
            ActionClass::Direction => "direction",
            ActionClass::PolicyChange => "policy_change",
            ActionClass::CredentialsChange => "credentials_change",
        }
    }
    /// Parse a wire name.
    pub fn parse(s: &str) -> Option<ActionClass> {
        ActionClass::ALL.into_iter().find(|c| c.as_str() == s)
    }
    /// Hard-rule classes: an attestation can never open the gate for these (doc section 6).
    pub fn is_hard_rule(self) -> bool {
        matches!(
            self,
            ActionClass::Delete
                | ActionClass::Spend
                | ActionClass::Publish
                | ActionClass::CredentialsChange
        )
    }
}

/// Why a decision was a denial (fixed vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    /// The requester may not do this.
    NotAuthorised,
    /// The subject is not what was described.
    WrongSubject,
    /// Too risky.
    TooRisky,
    /// Anything else.
    Other,
}

/// Who an actor is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A person.
    Human,
    /// An AI agent.
    Ai,
    /// A service.
    Service,
}

/// What the event says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Ask for approval of an exact subject.
    Request {
        /// Class of action.
        action_class: ActionClass,
        /// 64 hex: hash of the exact subject.
        subject_hash: String,
        /// Short token (commit SHA, stage id).
        subject_ref: String,
        /// How long an approval stays usable.
        valid_for_secs: u64,
    },
    /// Approve a request.
    Approve {
        /// Key id of a keyless human the signer attests for.
        on_behalf_of: Option<String>,
        /// Hash of the chat reference (never the text).
        basis_hash: Option<String>,
    },
    /// Deny a request.
    Deny {
        /// Why.
        reason: ReasonCode,
        /// Attestation target, as for approvals.
        on_behalf_of: Option<String>,
        /// Hash of the chat reference.
        basis_hash: Option<String>,
    },
    /// The executor records that an approval was used.
    Consume,
}

/// An unsigned event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Request id (derived for requests).
    pub request_id: String,
    /// Signer's key id.
    pub actor: String,
    /// Unix seconds claimed by the signer.
    pub ts: u64,
    /// The event body.
    pub body: Body,
}

impl Event {
    /// A request event; computes the derived request id.
    pub fn request(
        actor: &str,
        ts: u64,
        class: ActionClass,
        subject_hash: &str,
        subject_ref: &str,
        valid_for_secs: u64,
    ) -> Event {
        Event {
            request_id: codec::derive_request_id(actor, class, subject_hash, ts),
            actor: actor.into(),
            ts,
            body: Body::Request {
                action_class: class,
                subject_hash: subject_hash.into(),
                subject_ref: subject_ref.into(),
                valid_for_secs,
            },
        }
    }
    /// An approval event.
    pub fn approve(
        actor: &str,
        ts: u64,
        request_id: &str,
        on_behalf_of: Option<&str>,
        basis_hash: Option<&str>,
    ) -> Event {
        Event {
            request_id: request_id.into(),
            actor: actor.into(),
            ts,
            body: Body::Approve {
                on_behalf_of: on_behalf_of.map(Into::into),
                basis_hash: basis_hash.map(Into::into),
            },
        }
    }
    /// A denial event.
    pub fn deny(
        actor: &str,
        ts: u64,
        request_id: &str,
        reason: ReasonCode,
        on_behalf_of: Option<&str>,
        basis_hash: Option<&str>,
    ) -> Event {
        Event {
            request_id: request_id.into(),
            actor: actor.into(),
            ts,
            body: Body::Deny {
                reason,
                on_behalf_of: on_behalf_of.map(Into::into),
                basis_hash: basis_hash.map(Into::into),
            },
        }
    }
    /// A consume event.
    pub fn consume(actor: &str, ts: u64, request_id: &str) -> Event {
        Event {
            request_id: request_id.into(),
            actor: actor.into(),
            ts,
            body: Body::Consume,
        }
    }
}

/// An event with its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEvent {
    /// The event.
    pub event: Event,
    /// ML-DSA-65 signature, hex.
    pub sig: String,
}

/// Errors from encoding, decoding and signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    /// Never produced by the finished crate (kept for the S3b test helpers).
    NotImplemented,
    /// The event or payload is malformed; `0` names the field, never the value.
    Invalid(String),
}

impl std::error::Error for ApprovalError {}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalError::NotImplemented => write!(f, "{NOT_IMPLEMENTED}"),
            ApprovalError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

/// One registered actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// Public key (hex); empty for a human who has no signing key yet.
    pub pubkey_hex: String,
    /// Role.
    pub role: Role,
    /// Classes this actor may decide.
    pub may_approve: Vec<ActionClass>,
    /// Keyless humans this actor may attest for (key ids).
    pub may_attest_for: Vec<String>,
    /// Log index from which the key is revoked.
    pub revoked_at: Option<usize>,
}

/// The actor directory (key id to actor).
#[derive(Debug, Clone, Default)]
pub struct Directory {
    /// Registered actors by key id.
    pub actors: BTreeMap<String, Actor>,
}

/// Why an event was rejected at replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Not a valid approval event.
    Malformed,
    /// Signer not in the directory.
    UnknownActor,
    /// Key revoked at or before this index.
    RevokedKey,
    /// Signature does not verify.
    BadSignature,
    /// Approver may not decide this class (or is an AI/service without the right).
    NotAllowedApprover,
    /// Requester and approver are the same actor.
    SelfApproval,
    /// No earlier request with this id.
    NoSuchRequest,
    /// Decision after the request's expiry.
    Expired,
    /// A decision for this request already exists.
    Superseded,
    /// Timestamp too far in the future.
    FutureTimestamp,
    /// Attestation not permitted for this actor or class.
    AttestationNotPermitted,
    /// Consume without a valid approval, or twice.
    BadConsume,
}

/// A rejected record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// Log index of the record.
    pub index: usize,
    /// Why.
    pub reason: RejectReason,
}

/// Replayed approval state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// Records that looked like approval events but were not valid.
    pub rejected: Vec<Rejected>,
    pub(crate) requests: Vec<replay::ReqState>,
}

/// Which action classes accept an attestation. The hard-rule classes (delete, spend, publish,
/// credentials_change) never do, whatever this lists (doc section 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPolicy {
    /// Classes where "attested by" counts.
    pub accepted_for: Vec<ActionClass>,
}

/// The gate's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// A valid approval exists.
    Allowed {
        /// Request id.
        request_id: String,
        /// Key id that signed the approval.
        approver: String,
        /// True when the approval is an attestation.
        attested: bool,
    },
    /// No valid approval.
    Blocked(BlockReason),
}

/// Why the gate blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// No request at all.
    NoRequest,
    /// Requested, not decided.
    Pending,
    /// Denied.
    Denied,
    /// Approval expired.
    Expired,
    /// Approval already consumed.
    AlreadyUsed,
    /// A request exists for this class but for a different subject.
    SubjectMismatch,
    /// Approved only by attestation, which this class does not accept.
    AttestationNotAccepted,
}
