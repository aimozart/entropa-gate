//! Stage E-LABELS-3: two labels for the standards-retrieval stage (R1). Additive only; existing labels, kinds, controls and signatures
//! unchanged. corpus_version is an evidence.change label (a corpus version was sealed, or refused); retrieval_record is an evidence.access
//! label (a retrieval was answered, or abstained). The control codes are the E1 ones: no new control code is added.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use entropa_ledger::*;

fn probe() -> Probe {
    Probe::from_signing_key_hex(&"ef".repeat(32)).unwrap()
}

fn rec<'a>(kind: Kind, label: LabelCode, control: ControlCode) -> EvidenceRecord<'a> {
    EvidenceRecord {
        kind,
        label,
        decision: Decision::Allow,
        reason: ReasonCode::CheckPassed,
        control,
        total: 1234,
        passed: 5,
        flagged: 0,
        detail: "corpus_hash=aaaa|passages=nist/AU-9",
        run_id: "r1-demo-1",
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

const KINDS: [Kind; 5] = [
    Kind::EvidencePipelineRun,
    Kind::EvidenceControlCheck,
    Kind::EvidenceAccess,
    Kind::EvidenceChange,
    Kind::EvidencePolicy,
];

#[test]
fn k1_the_two_labels_are_appended_after_the_e1_labels_in_order() {
    // Test change (TH1): the label prereg_committed is appended after these, so the four are checked as a contiguous run, not as the very tail.
    let all: Vec<&str> = LabelCode::ALL.iter().map(|l| l.as_str()).collect();
    let at = all.iter().position(|w| *w == "crypto_inventory").unwrap();
    assert_eq!(
        &all[at..at + 4],
        [
            "crypto_inventory",
            "log_integrity_check",
            "corpus_version",
            "retrieval_record"
        ]
    );
    for w in ["corpus_version", "retrieval_record"] {
        assert!(LabelCode::parse(w).is_some(), "label {w}");
    }
    assert_eq!(LabelCode::parse("corpus_versions"), None);
}

#[test]
fn k2_each_new_label_fits_exactly_one_kind_and_is_not_a_platinum_label() {
    for (l, home) in [
        (LabelCode::CorpusVersion, Kind::EvidenceChange),
        (LabelCode::RetrievalRecord, Kind::EvidenceAccess),
    ] {
        for k in KINDS {
            let r = evidence_fields(&rec(k, l, ControlCode::Nist80053Au9));
            if k == home {
                must(r);
            } else {
                let e = expect_err(r);
                assert!(
                    format!("{e:?}").contains("does not belong to this kind"),
                    "{l:?} on {k:?}: {e:?}"
                );
            }
        }
        let e = expect_err(platinum_fields(&pd(l)));
        assert!(
            format!("{e:?}").contains("not a platinum label"),
            "{l:?}: {e:?}"
        );
    }
}

#[test]
fn k3_no_new_control_code_is_added_and_the_e1_codes_work_with_both_labels() {
    assert_eq!(ControlCode::ALL.len(), 22);
    for c in ControlCode::ALL {
        must(evidence_fields(&rec(
            Kind::EvidenceChange,
            LabelCode::CorpusVersion,
            *c,
        )));
        must(evidence_fields(&rec(
            Kind::EvidenceAccess,
            LabelCode::RetrievalRecord,
            *c,
        )));
    }
}

#[test]
fn k4_the_existing_labels_keep_their_kinds() {
    must(evidence_fields(&rec(
        Kind::EvidenceAccess,
        LabelCode::TableRead,
        ControlCode::Hipaa164312b,
    )));
    must(evidence_fields(&rec(
        Kind::EvidenceChange,
        LabelCode::Deploy,
        ControlCode::Hitrust10Sdlc,
    )));
    must(evidence_fields(&rec(
        Kind::EvidenceChange,
        LabelCode::CodeChange,
        ControlCode::Hitrust10Sdlc,
    )));
    expect_err(evidence_fields(&rec(
        Kind::EvidenceAccess,
        LabelCode::Deploy,
        ControlCode::Hitrust10Sdlc,
    )));
    expect_err(evidence_fields(&rec(
        Kind::EvidenceChange,
        LabelCode::TableRead,
        ControlCode::Hipaa164312b,
    )));
    expect_err(evidence_fields(&rec(
        Kind::EvidenceControlCheck,
        LabelCode::CorpusVersion,
        ControlCode::Nist80053Au9,
    )));
    expect_err(evidence_fields(&rec(
        Kind::EvidenceControlCheck,
        LabelCode::RetrievalRecord,
        ControlCode::EuAiActArt12,
    )));
}

#[test]
fn k5_the_new_events_sign_encode_and_verify() {
    for (k, l, c) in [
        (
            Kind::EvidenceChange,
            LabelCode::CorpusVersion,
            ControlCode::Nist80053Au9,
        ),
        (
            Kind::EvidenceAccess,
            LabelCode::RetrievalRecord,
            ControlCode::EuAiActArt12,
        ),
    ] {
        let f = must(evidence_fields(&rec(k, l, c)));
        let ev = must(sign_event(&probe(), &f));
        let payload = must(encode_event(&ev));
        assert_eq!(must(verify_event(&payload, &probe().pubkey_hex())), ev);
    }
}

fn say(
    kind: Kind,
    label: LabelCode,
    decision: Decision,
    reason: ReasonCode,
    t: u64,
    p: u64,
    fl: u64,
) -> String {
    let mut r = rec(kind, label, ControlCode::Nist80053Au9);
    r.decision = decision;
    r.reason = reason;
    (r.total, r.passed, r.flagged) = (t, p, fl);
    plain_english(&must(evidence_fields(&r)))
}

#[test]
fn k6_each_new_label_reads_in_plain_english_for_both_outcomes_without_ids_or_hashes() {
    let sealed = say(
        Kind::EvidenceChange,
        LabelCode::CorpusVersion,
        Decision::Allow,
        ReasonCode::CheckPassed,
        1234,
        5,
        0,
    );
    assert!(
        sealed.contains("corpus version was sealed")
            && sealed.contains("1,234 clauses")
            && sealed.contains("5 sources"),
        "{sealed}"
    );
    let refused = say(
        Kind::EvidenceChange,
        LabelCode::CorpusVersion,
        Decision::Deny,
        ReasonCode::CheckFailed,
        1234,
        0,
        1,
    );
    assert!(
        refused.contains("refused") && refused.contains("changed"),
        "{refused}"
    );
    let found = say(
        Kind::EvidenceAccess,
        LabelCode::RetrievalRecord,
        Decision::Allow,
        ReasonCode::CheckPassed,
        3,
        3,
        0,
    );
    assert!(
        found.contains("Retrieval") && found.contains("3 passages") && found.contains("returned"),
        "{found}"
    );
    let none = say(
        Kind::EvidenceAccess,
        LabelCode::RetrievalRecord,
        Decision::Deny,
        ReasonCode::CheckFailed,
        1,
        0,
        1,
    );
    assert!(
        none.contains("Retrieval") && none.contains("not in the corpus") && none != found,
        "{none}"
    );
    let mut all = vec![sealed.clone(), refused.clone(), found.clone(), none.clone()];
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 4, "each outcome reads differently");
    for s in [&sealed, &refused, &found, &none] {
        assert!(
            !s.contains("A role read a table")
                && !s.contains("A deploy")
                && !s.contains("sha256")
                && !s.contains("r1-demo"),
            "{s}"
        );
    }
    assert!(say(
        Kind::EvidenceAccess,
        LabelCode::TableRead,
        Decision::Allow,
        ReasonCode::CheckPassed,
        7,
        7,
        0
    )
    .contains("A role read a table"));
}
