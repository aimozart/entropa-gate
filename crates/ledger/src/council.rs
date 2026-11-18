//! Decision review council steps as data-minimal ledger events (stage C1). The reviewed text is hashed with the
//! session id and dropped: the ledger holds who acted, which step, the outcome as a closed code, and a hash.

use crate::event::{AgentMeta, EventFields};
use crate::platinum::has_valid_range_ssn_shape;
use crate::vocab::{Decision, Handle, Kind, LabelCode, ReasonCode, Tenant};
use crate::LedgerError;

/// One council step. `subject` is hashed and then dropped.
#[derive(Debug, Clone)]
pub struct CouncilStep<'a> {
    /// Which step (a council label).
    pub label: LabelCode,
    /// Who acted (a role handle, never a person's or internal name).
    pub actor: Handle,
    /// The outcome (`Allow` accepted, `Deny` rejected, `Hold` deferred, `Info` recorded).
    pub decision: Decision,
    /// Why, as a closed code.
    pub reason: ReasonCode,
    /// The finding, rebuttal, packet or decision text (hashed, never stored).
    pub subject: &'a str,
    /// The council session id (letters, digits and `. _ : / -`, at most 64).
    pub session_id: &'a str,
    /// Model metadata when a model produced the step.
    pub model: Option<AgentMeta>,
    /// Unix seconds.
    pub ts: u64,
    /// Key id of the signer (16 lowercase hex).
    pub key_id: String,
}

const MAX_TEXT: usize = 1024 * 1024;

fn invalid(field: &str, rule: &str) -> LedgerError {
    LedgerError::Invalid(format!("{field}: {rule}"))
}

fn framed(h: &mut blake3::Hasher, part: &[u8]) {
    h.update(&(part.len() as u64).to_be_bytes());
    h.update(part);
}

/// Build the event fields for a council step.
pub fn council_fields(s: &CouncilStep<'_>) -> Result<EventFields, LedgerError> {
    if !matches!(
        s.label,
        LabelCode::CouncilSession
            | LabelCode::CouncilPacket
            | LabelCode::CouncilFinding
            | LabelCode::CouncilRebuttal
            | LabelCode::CouncilDecision
    ) {
        return Err(invalid("label", "not a council label"));
    }
    let id_ok = !s.session_id.is_empty()
        && s.session_id.len() <= 64
        && s.session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'));
    if !id_ok {
        return Err(invalid("session_id", "must be 1 to 64 token characters"));
    }
    if s.key_id.len() != 16
        || !s
            .key_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid("key_id", "must be 16 lowercase hex"));
    }
    if s.subject.len() > MAX_TEXT {
        return Err(invalid("text", "too large"));
    }
    if has_valid_range_ssn_shape(s.subject) {
        return Err(invalid(
            "text",
            "holds an identifier shape in a valid range",
        ));
    }
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-council-subject-v1\0");
    framed(&mut h, s.subject.as_bytes());
    framed(&mut h, s.session_id.as_bytes());
    Ok(EventFields {
        kind: Kind::CouncilStep,
        tenant: Tenant::Entropa,
        key_id: s.key_id.clone(),
        handle: s.actor,
        ts: s.ts,
        subject_hash: hex::encode(h.finalize().as_bytes()),
        label: s.label,
        decision: s.decision,
        reason: s.reason,
        approval_ref: None,
        agent: s.model.clone(),
        role: None,
        attested_by: None,
        pubkey_fingerprint: None,
        evidence: None,
    })
}
