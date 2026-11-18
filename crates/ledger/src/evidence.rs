//! Audit-evidence events (stage P3): pipeline runs, control checks, access decisions, changes and
//! policy events, each tagged with the control it supports. Data-minimal: counts, closed codes and a
//! hash of the detail text, never data.

use crate::event::MAX_SAFE_INT;
use crate::event::{EventFields, EvidenceMeta};
use crate::platinum::has_valid_range_ssn_shape;
use crate::vocab::{ControlCode, Decision, Handle, Kind, LabelCode, ReasonCode, Tenant};
use crate::LedgerError;

/// One piece of audit evidence. `detail` is hashed and dropped: it never reaches the ledger.
#[derive(Debug, Clone)]
pub struct EvidenceRecord<'a> {
    /// One of the five evidence kinds.
    pub kind: Kind,
    /// What it is about (must belong to the kind).
    pub label: LabelCode,
    /// `Allow` = passed, `Deny` = failed, `Info` = recorded.
    pub decision: Decision,
    /// Why, as a closed code.
    pub reason: ReasonCode,
    /// The control supported.
    pub control: ControlCode,
    /// Items examined.
    pub total: u64,
    /// Items passed or returned.
    pub passed: u64,
    /// Items flagged, quarantined or masked.
    pub flagged: u64,
    /// Free detail (hashed and dropped).
    pub detail: &'a str,
    /// The run or change id (token characters, at most 64).
    pub run_id: &'a str,
    /// Unix seconds.
    pub ts: u64,
    /// Key id of the signer (16 lowercase hex).
    pub key_id: String,
}

const MAX_TEXT: usize = 1024 * 1024;

fn invalid(field: &str, rule: &str) -> LedgerError {
    LedgerError::Invalid(format!("{field}: {rule}"))
}

fn label_fits(kind: Kind, label: LabelCode) -> bool {
    match kind {
        Kind::EvidencePipelineRun => {
            matches!(
                label,
                LabelCode::Bronze | LabelCode::Silver | LabelCode::Gold | LabelCode::Platinum
            )
        }
        Kind::EvidenceControlCheck => matches!(
            label,
            LabelCode::RlsTest
                | LabelCode::MaskingCheck
                | LabelCode::KAnonymity
                | LabelCode::CanaryScan
                | LabelCode::IdentifierRange
                | LabelCode::SecretScan
                | LabelCode::CiTests
                | LabelCode::CaseOutcome
                | LabelCode::CryptoInventory
                | LabelCode::LogIntegrityCheck
        ),
        Kind::EvidenceAccess => matches!(label, LabelCode::TableRead | LabelCode::RetrievalRecord),
        Kind::EvidenceChange => matches!(
            label,
            LabelCode::Deploy
                | LabelCode::Rollback
                | LabelCode::SchemaChange
                | LabelCode::KeyRotation
                | LabelCode::CodeChange
                | LabelCode::CorpusVersion
        ),
        Kind::EvidencePolicy => matches!(
            label,
            LabelCode::PolicyApproved
                | LabelCode::PolicyVerdict
                | LabelCode::ApprovalRequested
                | LabelCode::ApprovalDenied
        ),
        _ => false,
    }
}

fn framed(h: &mut blake3::Hasher, part: &[u8]) {
    h.update(&(part.len() as u64).to_be_bytes());
    h.update(part);
}

/// Build the event fields for a piece of evidence. The subject hash is
/// `BLAKE3("entropa-evidence-subject-v1" 0x00 || frame(detail) || frame(run_id))`.
pub fn evidence_fields(r: &EvidenceRecord<'_>) -> Result<EventFields, LedgerError> {
    if !label_fits(r.kind, r.label) {
        return Err(invalid("label", "does not belong to this kind"));
    }
    let run_ok = !r.run_id.is_empty()
        && r.run_id.len() <= 64
        && r.run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'));
    if !run_ok {
        return Err(invalid("run_id", "must be 1 to 64 token characters"));
    }
    if r.key_id.len() != 16
        || !r
            .key_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid("key_id", "must be 16 lowercase hex"));
    }
    if r.total > MAX_SAFE_INT || r.passed > r.total || r.flagged > r.total {
        return Err(invalid("counts", "must be consistent and within range"));
    }
    if r.detail.len() > MAX_TEXT {
        return Err(invalid("detail", "too large"));
    }
    if has_valid_range_ssn_shape(r.detail) {
        return Err(invalid(
            "detail",
            "holds an identifier shape in a valid range",
        ));
    }
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-evidence-subject-v1\0");
    framed(&mut h, r.detail.as_bytes());
    framed(&mut h, r.run_id.as_bytes());
    Ok(EventFields {
        kind: r.kind,
        tenant: Tenant::Hippagrchealthcare,
        key_id: r.key_id.clone(),
        handle: Handle::AgentHippagrchealthcare,
        ts: r.ts,
        subject_hash: hex::encode(h.finalize().as_bytes()),
        label: r.label,
        decision: r.decision,
        reason: r.reason,
        approval_ref: None,
        agent: None,
        role: None,
        attested_by: None,
        pubkey_fingerprint: None,
        evidence: Some(EvidenceMeta {
            control: r.control,
            total: r.total,
            passed: r.passed,
            flagged: r.flagged,
        }),
    })
}
