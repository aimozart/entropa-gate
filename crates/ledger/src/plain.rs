//! Plain-English descriptions of events. They are generated from the closed codes and the counts only, with fixed
//! templates, so no free text is stored and a description can never drift from the record it describes.

use crate::event::EventFields;
use crate::vocab::{ControlCode, Decision, Kind, LabelCode, ReasonCode};

impl ControlCode {
    /// A plain title for the control (names only; no framework text is reproduced).
    pub fn title(self) -> &'static str {
        match self {
            ControlCode::Hipaa164308a1 => "HIPAA security management (164.308(a)(1))",
            ControlCode::Hipaa164308a4 => "HIPAA information access management (164.308(a)(4))",
            ControlCode::Hipaa164312a1 => "HIPAA access control (164.312(a))",
            ControlCode::Hipaa164312b => "HIPAA audit controls (164.312(b))",
            ControlCode::Hipaa164312c1 => "HIPAA integrity (164.312(c))",
            ControlCode::Hipaa164312d => "HIPAA person or entity authentication (164.312(d))",
            ControlCode::Hipaa164312e1 => "HIPAA transmission security (164.312(e))",
            ControlCode::Hitrust01AccessControl => "HITRUST access control",
            ControlCode::Hitrust06Compliance => "HITRUST compliance",
            ControlCode::Hitrust09Operations => "HITRUST operations management",
            ControlCode::Hitrust10Sdlc => "HITRUST secure development and maintenance",
            ControlCode::Hitrust13Privacy => "HITRUST privacy practices",
            ControlCode::PolicyP0DataSafety => "our data-safety policy (P0)",
            ControlCode::PolicyP3SeparationOfDuties => "our separation-of-duties policy (P3)",
            ControlCode::PciDss10_3_4 => "PCI DSS 10.3.4",
            ControlCode::PciDss12_3_3 => "PCI DSS 12.3.3",
            ControlCode::DoraRtsArt6 => "DORA RTS Art. 6",
            ControlCode::DoraRtsArt12 => "DORA RTS Art. 12",
            ControlCode::Nist80053Au9 => "NIST SP 800-53 AU-9",
            ControlCode::Nist80053Au10 => "NIST SP 800-53 AU-10",
            ControlCode::EuAiActArt12 => "EU AI Act Art. 12",
            ControlCode::EuAiActArt19 => "EU AI Act Art. 19",
        }
    }
}

/// Digits with thousands separators: 7000 becomes "7,000".
fn n(v: u64) -> String {
    let s = v.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn plural(v: u64, one: &str, many: &str) -> String {
    format!("{} {}", n(v), if v == 1 { one } else { many })
}

/// Describe an event in plain English.
pub fn plain_english(f: &EventFields) -> String {
    let passed = f.decision == Decision::Allow;
    let supports = |f: &EventFields| {
        f.evidence
            .as_ref()
            .map(|e| format!(" Supports {}.", e.control.title()))
            .unwrap_or_default()
    };
    let (t, p, fl) = f
        .evidence
        .as_ref()
        .map_or((0, 0, 0), |e| (e.total, e.passed, e.flagged));
    let body = match (f.kind, f.label) {
        (Kind::CouncilStep, LabelCode::CouncilSession) => {
            if f.reason == ReasonCode::CouncilNoQuorum {
                "A council session could not meet its quorum, so nothing changes.".to_string()
            } else {
                "The council scheduler recorded a session event.".to_string()
            }
        }
        (Kind::CouncilStep, LabelCode::CouncilPacket) => {
            "The orchestrator compiled the review packet: the recorded decisions and their outcomes for this session.".to_string()
        }
        (Kind::CouncilStep, LabelCode::CouncilFinding) => {
            "The critic filed a finding about a recorded decision. Only a hash of the finding is kept here.".to_string()
        }
        (Kind::CouncilStep, LabelCode::CouncilRebuttal) => {
            "The contestor argued against a finding. Only a hash of the rebuttal is kept here.".to_string()
        }
        (Kind::CouncilStep, LabelCode::CouncilDecision) => match f.reason {
            ReasonCode::CouncilAccepted => "The Human Principal accepted a finding. The council proposes; the change goes through the approvals gate.".to_string(),
            ReasonCode::CouncilRejected => "The Human Principal rejected a finding. Nothing changes.".to_string(),
            _ => "The Human Principal deferred a finding to a later session. Nothing changes.".to_string(),
        },
        (Kind::PlatinumDecision, LabelCode::NlQuery) => match f.reason {
            ReasonCode::GuardRefused => "The assistant turned a question into a read-only database query. The SQL guard refused it.".to_string(),
            ReasonCode::InjectionSuspected => "The input looked like a prompt injection and was blocked.".to_string(),
            _ => "The assistant turned a question into a read-only database query. The SQL guard allowed it.".to_string(),
        },
        (Kind::PlatinumDecision, LabelCode::RagAnswer) => {
            if f.decision == Decision::Hold || f.reason == ReasonCode::NeedsReview {
                "The assistant answered a question without citing a source, so the answer was held for review.".to_string()
            } else {
                "The assistant answered a question and cited its sources.".to_string()
            }
        }
        (Kind::PlatinumDecision, LabelCode::ClaimsTriage) => match f.decision {
            Decision::Deny => "A denied claim was triaged. The policy gate refused the proposed action, so the claim goes to a person.".to_string(),
            Decision::Escalate => "A denied claim was triaged and sent to a person to decide.".to_string(),
            _ => "A denied claim was triaged and a next step was chosen within the policy limits.".to_string(),
        },
        (Kind::PlatinumDecision, LabelCode::MlScore) => {
            "A model scored a record. The features and the score are not stored; only a hash of them is.".to_string()
        }
        (Kind::EvidencePipelineRun, layer) => {
            let name = match layer {
                LabelCode::Bronze => "Bronze",
                LabelCode::Silver => "Silver",
                LabelCode::Gold => "Gold",
                _ => "Platinum",
            };
            let adds_up = p + fl == t;
            format!(
                "{name} layer, nightly run: {} came in, {} were valid and {} were quarantined. {}",
                plural(t, "row", "rows"),
                n(p),
                n(fl),
                if adds_up {
                    "Valid plus quarantined equals the input, so the integrity check passed."
                } else {
                    "Valid plus quarantined do not add up to the input, so the integrity check failed."
                }
            )
        }
        (Kind::EvidenceControlCheck, LabelCode::CiTests) => format!(
            "{} automated tests ran: {} passed and {} failed.",
            n(t),
            n(p),
            n(fl)
        ),
        (Kind::EvidenceControlCheck, LabelCode::SecretScan) => if passed {
            "Secret scan: no secrets were found in the code and its history.".to_string()
        } else {
            "Secret scan: a possible secret was found and needs review.".to_string()
        },
        (Kind::EvidenceControlCheck, LabelCode::IdentifierRange) => if passed {
            "Identifier check: no real-looking identifiers were found; only reserved invalid ranges are used.".to_string()
        } else {
            format!("Identifier check: {} real-looking identifier(s) were found and must be removed.", n(fl))
        },
        (Kind::EvidenceControlCheck, LabelCode::RlsTest) => format!(
            "Row-level security test: {} probes were run as the wrong user; {} correctly returned nothing and {} leaked.",
            n(t),
            n(p),
            n(fl)
        ),
        (Kind::EvidenceControlCheck, LabelCode::MaskingCheck) => format!(
            "Masking check: {} fields were examined; {} were masked correctly and {} were not.",
            n(t),
            n(p),
            n(fl)
        ),
        (Kind::EvidenceControlCheck, LabelCode::KAnonymity) => format!(
            "Privacy (k-anonymity) check: {} groups were examined; {} are safe to show (small groups are suppressed) and {} were too small and still visible.",
            n(t),
            n(p),
            n(fl)
        ),
        (Kind::EvidenceControlCheck, LabelCode::CanaryScan) => if passed {
            "Leak scan: the planted canary strings were not found anywhere they should not be.".to_string()
        } else {
            "Leak scan: a planted canary string appeared where it should not.".to_string()
        },
        (Kind::EvidenceControlCheck, LabelCode::CaseOutcome) => if passed {
            "Case outcome: the decision matched the known outcome.".to_string()
        } else {
            "Case outcome: the decision did not match the known outcome, and the mismatch is recorded.".to_string()
        },
        (Kind::EvidenceControlCheck, LabelCode::CryptoInventory) => format!(
            "Crypto inventory: {} hosts examined, {} listed with their TLS settings, {} did not answer.",
            n(t),
            n(p),
            n(fl)
        ),
        (Kind::EvidenceControlCheck, LabelCode::LogIntegrityCheck) => if passed {
            "Log integrity: the ledger was verified from start to end and nothing had been changed.".to_string()
        } else {
            "Log integrity: verification failed, so the ledger was changed or damaged, and the failure is recorded.".to_string()
        },
        (Kind::EvidenceControlCheck, _) => format!("A control check ran: {} examined, {} passed, {} failed.", n(t), n(p), n(fl)),
        (Kind::EvidenceAccess, LabelCode::RetrievalRecord) => if passed {
            format!("Retrieval: {} returned from the sealed standards corpus.", plural(t, "passage was", "passages were"))
        } else {
            "Retrieval: nothing in the corpus matched, so no answer was given (not in the corpus).".to_string()
        },
        (Kind::EvidenceAccess, _) => format!(
            "A role read a table: {} were requested, {} returned and {} masked.",
            plural(t, "row", "rows"),
            n(p),
            n(fl)
        )
        .replace("1 row were", "1 row was"),
        (Kind::EvidenceChange, LabelCode::CodeChange) => format!("A code change was recorded ({}).", plural(t, "file", "files")),
        (Kind::EvidenceChange, LabelCode::CorpusVersion) => if passed {
            format!("A standards corpus version was sealed: {} from {}.", plural(t, "clause", "clauses"), plural(p, "source", "sources"))
        } else {
            "A standards corpus version was refused: a source changed under the same version name, so nothing was overwritten.".to_string()
        },
        (Kind::EvidenceChange, LabelCode::PreregCommitted) => "A pre-registration was committed: a signed record of what would be tested was anchored here, as a hash only.".to_string(),
        (Kind::EvidenceChange, LabelCode::Deploy) => "A deploy was recorded.".to_string(),
        (Kind::EvidenceChange, LabelCode::Rollback) => "A rollback was recorded.".to_string(),
        (Kind::EvidenceChange, LabelCode::SchemaChange) => "A schema change was recorded.".to_string(),
        (Kind::EvidenceChange, LabelCode::KeyRotation) => "A key rotation was recorded.".to_string(),
        (Kind::EvidencePolicy, LabelCode::PolicyVerdict) => if passed {
            "The policy gate allowed a proposed action.".to_string()
        } else {
            "The policy gate refused a proposed action.".to_string()
        },
        (Kind::EvidencePolicy, LabelCode::ApprovalRequested) => "A human approval was requested and is waiting for a decision.".to_string(),
        (Kind::EvidencePolicy, LabelCode::ApprovalDenied) => "A human approval was denied, or expired without a decision, so nothing proceeds.".to_string(),
        (Kind::EvidencePolicy, _) => "A policy approval was recorded.".to_string(),
        _ => "An event was recorded.".to_string(),
    };
    format!("{body}{}", supports(f))
}
