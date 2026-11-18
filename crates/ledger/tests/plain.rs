//! Plain-English descriptions of events, generated from closed codes and counts only (no free text is stored).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_ledger::*;

fn ev<'a>(
    kind: Kind,
    label: LabelCode,
    decision: Decision,
    reason: ReasonCode,
    t: u64,
    p: u64,
    f: u64,
) -> EvidenceRecord<'a> {
    EvidenceRecord {
        kind,
        label,
        decision,
        reason,
        control: ControlCode::Hipaa164312c1,
        total: t,
        passed: p,
        flagged: f,
        detail: "x",
        run_id: "run-1",
        ts: START,
        key_id: "0123456789abcdef".into(),
    }
}

fn say(r: EvidenceRecord<'_>) -> String {
    plain_english(&must(evidence_fields(&r)))
}

#[test]
fn n1_a_silver_run_reads_like_a_sentence_with_commas_and_the_invariant() {
    let s = say(ev(
        Kind::EvidencePipelineRun,
        LabelCode::Silver,
        Decision::Allow,
        ReasonCode::CheckPassed,
        7000,
        6210,
        790,
    ));
    assert!(s.contains("Silver layer"), "{s}");
    assert!(s.contains("7,000 rows came in"), "{s}");
    assert!(s.contains("6,210 were valid"), "{s}");
    assert!(s.contains("790 were quarantined"), "{s}");
    assert!(s.contains("integrity check passed"), "{s}");
    assert!(s.contains("HIPAA integrity"), "{s}");
}

#[test]
fn n2_a_broken_invariant_is_said_plainly() {
    let s = say(ev(
        Kind::EvidencePipelineRun,
        LabelCode::Silver,
        Decision::Deny,
        ReasonCode::CheckFailed,
        7000,
        6000,
        500,
    ));
    assert!(s.contains("do not add up"), "{s}");
    assert!(s.contains("integrity check failed"), "{s}");
}

#[test]
fn n3_control_checks_say_what_was_tested_and_the_outcome() {
    let s = say(ev(
        Kind::EvidenceControlCheck,
        LabelCode::CiTests,
        Decision::Allow,
        ReasonCode::CheckPassed,
        53,
        53,
        0,
    ));
    assert!(
        s.contains("53 automated tests") && s.contains("53 passed") && s.contains("0 failed"),
        "{s}"
    );
    let s = say(ev(
        Kind::EvidenceControlCheck,
        LabelCode::SecretScan,
        Decision::Deny,
        ReasonCode::CheckFailed,
        1,
        0,
        1,
    ));
    assert!(
        s.contains("Secret scan") && s.to_lowercase().contains("found"),
        "{s}"
    );
    let s = say(ev(
        Kind::EvidenceControlCheck,
        LabelCode::RlsTest,
        Decision::Allow,
        ReasonCode::CheckPassed,
        25,
        25,
        0,
    ));
    assert!(s.contains("Row-level security") && s.contains("25"), "{s}");
}

#[test]
fn n4_access_and_changes_read_naturally() {
    let s = say(ev(
        Kind::EvidenceAccess,
        LabelCode::TableRead,
        Decision::Allow,
        ReasonCode::CheckPassed,
        100,
        80,
        20,
    ));
    assert!(
        s.contains("100 rows were requested")
            && s.contains("80 returned")
            && s.contains("20 masked"),
        "{s}"
    );
    let s = say(ev(
        Kind::EvidenceChange,
        LabelCode::CodeChange,
        Decision::Info,
        ReasonCode::CheckPassed,
        3,
        3,
        0,
    ));
    assert!(s.contains("code change") && s.contains("3 files"), "{s}");
    let s = say(ev(
        Kind::EvidenceChange,
        LabelCode::Deploy,
        Decision::Info,
        ReasonCode::CheckPassed,
        1,
        1,
        0,
    ));
    assert!(s.to_lowercase().contains("deploy"), "{s}");
}

#[test]
fn n5_ai_decisions_are_described_the_same_way() {
    use entropa_ledger::{platinum_fields, AgentMeta, PlatinumDecision, Provider};
    let d = |label, decision, reason| PlatinumDecision {
        label,
        decision,
        reason,
        input: "q",
        output: "a",
        run_id: "run-1",
        model: AgentMeta {
            provider: Provider::Vertex,
            model_id: "m".into(),
            input_tokens: 1,
            output_tokens: 1,
            cost_micro_usd: 1,
        },
        ts: START,
        key_id: "0123456789abcdef".into(),
    };
    let s = plain_english(&must(platinum_fields(&d(
        LabelCode::NlQuery,
        Decision::Allow,
        ReasonCode::GuardPassed,
    ))));
    assert!(
        s.contains("read-only database query") && s.contains("allowed"),
        "{s}"
    );
    let s = plain_english(&must(platinum_fields(&d(
        LabelCode::NlQuery,
        Decision::Deny,
        ReasonCode::GuardRefused,
    ))));
    assert!(s.contains("refused"), "{s}");
    let s = plain_english(&must(platinum_fields(&d(
        LabelCode::RagAnswer,
        Decision::Hold,
        ReasonCode::NeedsReview,
    ))));
    assert!(s.contains("held for review"), "{s}");
    let s = plain_english(&must(platinum_fields(&d(
        LabelCode::MlScore,
        Decision::Info,
        ReasonCode::WithinLimits,
    ))));
    assert!(s.contains("scored"), "{s}");
}

#[test]
fn n6_the_description_never_contains_hashes_or_ids() {
    let s = say(ev(
        Kind::EvidencePipelineRun,
        LabelCode::Gold,
        Decision::Allow,
        ReasonCode::CheckPassed,
        10,
        9,
        1,
    ));
    assert!(!s.contains("run-1"), "{s}");
    assert!(
        !s.split_whitespace()
            .any(|w| w.len() >= 32 && w.chars().all(|c| c.is_ascii_hexdigit())),
        "{s}"
    );
}

#[test]
fn n7_k_anonymity_says_small_groups_are_hidden_not_failed() {
    let s = say(ev(
        Kind::EvidenceControlCheck,
        LabelCode::KAnonymity,
        Decision::Allow,
        ReasonCode::CheckPassed,
        20,
        20,
        0,
    ));
    assert!(
        s.contains("20 groups were examined")
            && s.contains("suppressed")
            && s.contains("0 were too small and still visible"),
        "{s}"
    );
}
