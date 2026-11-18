//! Stage E-LABELS: five labels for the claims-triage showcase. Additive only; existing labels, kinds and signatures unchanged.
//! claims_triage is a platinum.decision label; policy_verdict, approval_requested and approval_denied are evidence.policy labels;
//! case_outcome is an evidence.control_check label (a decision checked against the known outcome: counts of passed and flagged).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use entropa_ledger::*;

fn probe() -> Probe {
    Probe::from_signing_key_hex(&"ef".repeat(32)).unwrap()
}

fn rec<'a>(kind: Kind, label: LabelCode) -> EvidenceRecord<'a> {
    EvidenceRecord {
        kind,
        label,
        decision: Decision::Allow,
        reason: ReasonCode::CheckPassed,
        control: ControlCode::PolicyP0DataSafety,
        total: 1,
        passed: 1,
        flagged: 0,
        detail: "case=SYN-CASE-0001|action=appeal",
        run_id: "triage-SYN-CASE-0001",
        ts: START,
        key_id: "0123456789abcdef".into(),
    }
}

fn pd(label: LabelCode) -> PlatinumDecision<'static> {
    PlatinumDecision {
        label,
        decision: Decision::Escalate,
        reason: ReasonCode::HumanRequired,
        input: "sha256:aaaa",
        output: "needs_human|UNDETERMINED|model",
        run_id: "triage-SYN-CASE-0001",
        model: AgentMeta {
            provider: Provider::Vertex,
            model_id: "gemini-3.8-flash".into(),
            input_tokens: 0,
            output_tokens: 0,
            cost_micro_usd: 0,
        },
        ts: START,
        key_id: "0123456789abcdef".into(),
    }
}

const EVIDENCE_KINDS: [Kind; 5] = [
    Kind::EvidencePipelineRun,
    Kind::EvidenceControlCheck,
    Kind::EvidenceAccess,
    Kind::EvidenceChange,
    Kind::EvidencePolicy,
];

#[test]
fn t1_the_five_labels_are_appended_after_the_original_labels_in_order() {
    // E-LABELS-2 appends two more labels after these five, so the five are checked as a contiguous run that starts
    // right after council_decision (the last original label), not as the very tail.
    let all: Vec<&str> = LabelCode::ALL.iter().map(|l| l.as_str()).collect();
    let start = all.iter().position(|w| *w == "council_decision").unwrap() + 1;
    assert_eq!(
        &all[start..start + 5],
        [
            "claims_triage",
            "policy_verdict",
            "approval_requested",
            "approval_denied",
            "case_outcome"
        ]
    );
    for w in [
        "claims_triage",
        "policy_verdict",
        "approval_requested",
        "approval_denied",
        "case_outcome",
    ] {
        assert!(LabelCode::parse(w).is_some(), "label {w}");
    }
}

#[test]
fn t2_claims_triage_is_a_platinum_label() {
    let f = must(platinum_fields(&pd(LabelCode::ClaimsTriage)));
    assert_eq!(f.kind, Kind::PlatinumDecision);
    assert_eq!(f.label, LabelCode::ClaimsTriage);
    assert_eq!(f.decision, Decision::Escalate);
}

#[test]
fn t3_the_other_new_labels_are_not_platinum_labels() {
    for l in [
        LabelCode::PolicyVerdict,
        LabelCode::ApprovalRequested,
        LabelCode::ApprovalDenied,
        LabelCode::CaseOutcome,
    ] {
        let e = expect_err(platinum_fields(&pd(l)));
        assert!(
            format!("{e:?}").contains("not a platinum label"),
            "{l:?}: {e:?}"
        );
    }
}

#[test]
fn t4_policy_labels_fit_evidence_policy_and_no_other_evidence_kind() {
    for l in [
        LabelCode::PolicyApproved,
        LabelCode::PolicyVerdict,
        LabelCode::ApprovalRequested,
        LabelCode::ApprovalDenied,
    ] {
        for k in EVIDENCE_KINDS {
            let r = evidence_fields(&rec(k, l));
            if k == Kind::EvidencePolicy {
                must(r);
            } else {
                let e = expect_err(r);
                assert!(
                    format!("{e:?}").contains("does not belong to this kind"),
                    "{l:?} on {k:?}: {e:?}"
                );
            }
        }
    }
}

#[test]
fn t5_case_outcome_fits_evidence_control_check_only() {
    for k in EVIDENCE_KINDS {
        let r = evidence_fields(&rec(k, LabelCode::CaseOutcome));
        if k == Kind::EvidenceControlCheck {
            must(r);
        } else {
            expect_err(r);
        }
    }
}

#[test]
fn t6_claims_triage_is_refused_on_every_evidence_kind() {
    for k in EVIDENCE_KINDS {
        expect_err(evidence_fields(&rec(k, LabelCode::ClaimsTriage)));
    }
}

#[test]
fn t7_existing_labels_keep_their_kinds() {
    must(evidence_fields(&rec(
        Kind::EvidenceChange,
        LabelCode::CodeChange,
    )));
    expect_err(evidence_fields(&rec(
        Kind::EvidencePolicy,
        LabelCode::CodeChange,
    )));
    expect_err(evidence_fields(&rec(
        Kind::EvidenceChange,
        LabelCode::PolicyApproved,
    )));
    must(evidence_fields(&rec(
        Kind::EvidenceControlCheck,
        LabelCode::CanaryScan,
    )));
    expect_err(evidence_fields(&rec(
        Kind::EvidenceControlCheck,
        LabelCode::PolicyApproved,
    )));
    for l in [LabelCode::NlQuery, LabelCode::MlScore, LabelCode::RagAnswer] {
        must(platinum_fields(&pd(l)));
    }
    expect_err(platinum_fields(&pd(LabelCode::CaseReview)));
}

#[test]
fn t8_the_new_events_sign_encode_and_verify() {
    let fields = [
        must(platinum_fields(&pd(LabelCode::ClaimsTriage))),
        must(evidence_fields(&rec(
            Kind::EvidencePolicy,
            LabelCode::ApprovalRequested,
        ))),
        must(evidence_fields(&rec(
            Kind::EvidencePolicy,
            LabelCode::PolicyVerdict,
        ))),
        must(evidence_fields(&rec(
            Kind::EvidencePolicy,
            LabelCode::ApprovalDenied,
        ))),
        must(evidence_fields(&rec(
            Kind::EvidenceControlCheck,
            LabelCode::CaseOutcome,
        ))),
    ];
    for f in fields {
        let ev = must(sign_event(&probe(), &f));
        let payload = must(encode_event(&ev));
        assert_eq!(must(verify_event(&payload, &probe().pubkey_hex())), ev);
    }
}

fn say(f: &EventFields) -> String {
    plain_english(f)
}

#[test]
fn t9_each_new_label_has_its_own_plain_english_sentence_without_ids() {
    let tri = say(&must(platinum_fields(&pd(LabelCode::ClaimsTriage))));
    assert!(tri.contains("denied claim"), "{tri}");
    let mut seen = vec![tri];
    for (k, l) in [
        (Kind::EvidencePolicy, LabelCode::PolicyVerdict),
        (Kind::EvidencePolicy, LabelCode::ApprovalRequested),
        (Kind::EvidencePolicy, LabelCode::ApprovalDenied),
        (Kind::EvidenceControlCheck, LabelCode::CaseOutcome),
    ] {
        let s = say(&must(evidence_fields(&rec(k, l))));
        assert!(
            !s.contains("An event was recorded.") && !s.contains("A policy approval was recorded."),
            "{l:?}: {s}"
        );
        assert!(!s.contains("SYN-CASE") && !s.contains("triage-"), "{s}");
        seen.push(s);
    }
    let n = seen.len();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), n, "each label reads differently");
    let ok = say(&must(evidence_fields(&rec(
        Kind::EvidencePolicy,
        LabelCode::PolicyApproved,
    ))));
    assert!(ok.contains("policy approval"), "{ok}");
}
