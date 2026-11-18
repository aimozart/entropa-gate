//! Platinum-layer AI decisions as data-minimal ledger events (stage P1). Stub: red tests first.

use crate::event::{AgentMeta, EventFields};
use crate::vocab::{Decision, Handle, Kind, LabelCode, ReasonCode, Tenant};
use crate::LedgerError;

/// One AI decision in the platinum layer. `input` and `output` are hashed and then dropped:
/// no event ever carries them.
#[derive(Debug, Clone)]
pub struct PlatinumDecision<'a> {
    /// What kind of decision (`NlQuery`, `MlScore` or `RagAnswer`).
    pub label: LabelCode,
    /// The outcome.
    pub decision: Decision,
    /// Why.
    pub reason: ReasonCode,
    /// The question, SQL, feature row or prompt (hashed, never stored).
    pub input: &'a str,
    /// The answer, result or score (hashed, never stored).
    pub output: &'a str,
    /// The pipeline run id (letters, digits and `. _ : / -`, at most 64).
    pub run_id: &'a str,
    /// Model metadata (ids and counts only).
    pub model: AgentMeta,
    /// Unix seconds.
    pub ts: u64,
    /// Key id of the signer (16 lowercase hex).
    pub key_id: String,
}

const MAX_TEXT: usize = 1024 * 1024;

fn invalid(field: &str, rule: &str) -> LedgerError {
    LedgerError::Invalid(format!("{field}: {rule}"))
}

/// True when `text` holds a nine-digit identifier shape in a VALID SSN range (P0): area not 000,
/// 666 or 9xx, group not 00, serial not 0000. The reserved invalid range (area 9xx) is allowed.
pub(crate) fn has_valid_range_ssn_shape(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() < 11 {
        return false;
    }
    (0..=b.len() - 11).any(|i| {
        let w = &b[i..i + 11];
        let digits = |r: std::ops::Range<usize>| w[r].iter().all(u8::is_ascii_digit);
        let edge_ok = (i == 0 || !b[i - 1].is_ascii_digit())
            && (i + 11 == b.len() || !b[i + 11].is_ascii_digit());
        edge_ok
            && digits(0..3)
            && w[3] == b'-'
            && digits(4..6)
            && w[6] == b'-'
            && digits(7..11)
            && &w[0..3] != b"000"
            && &w[0..3] != b"666"
            && w[0] != b'9'
            && &w[4..6] != b"00"
            && &w[7..11] != b"0000"
    })
}

fn framed(h: &mut blake3::Hasher, part: &[u8]) {
    h.update(&(part.len() as u64).to_be_bytes());
    h.update(part);
}

/// Build the event fields for a platinum decision. The subject hash is
/// `BLAKE3("entropa-platinum-subject-v1" 0x00 || frame(input) || frame(output) || frame(run_id))`
/// with each part framed by an 8-byte big-endian length.
pub fn platinum_fields(d: &PlatinumDecision<'_>) -> Result<EventFields, LedgerError> {
    if !matches!(
        d.label,
        LabelCode::NlQuery | LabelCode::MlScore | LabelCode::RagAnswer | LabelCode::ClaimsTriage
    ) {
        return Err(invalid("label", "not a platinum label"));
    }
    let run_ok = !d.run_id.is_empty()
        && d.run_id.len() <= 64
        && d.run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'));
    if !run_ok {
        return Err(invalid("run_id", "must be 1 to 64 token characters"));
    }
    if d.key_id.len() != 16
        || !d
            .key_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid("key_id", "must be 16 lowercase hex"));
    }
    if d.input.len() > MAX_TEXT || d.output.len() > MAX_TEXT {
        return Err(invalid("text", "too large"));
    }
    if has_valid_range_ssn_shape(d.input) || has_valid_range_ssn_shape(d.output) {
        return Err(invalid(
            "text",
            "holds an identifier shape in a valid range",
        ));
    }
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-platinum-subject-v1\0");
    framed(&mut h, d.input.as_bytes());
    framed(&mut h, d.output.as_bytes());
    framed(&mut h, d.run_id.as_bytes());
    Ok(EventFields {
        kind: Kind::PlatinumDecision,
        tenant: Tenant::Hippagrchealthcare,
        key_id: d.key_id.clone(),
        handle: Handle::AgentHippagrchealthcare,
        ts: d.ts,
        subject_hash: hex::encode(h.finalize().as_bytes()),
        label: d.label,
        decision: d.decision,
        reason: d.reason,
        approval_ref: None,
        agent: Some(d.model.clone()),
        role: None,
        attested_by: None,
        pubkey_fingerprint: None,
        evidence: None,
    })
}
