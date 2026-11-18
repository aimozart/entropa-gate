//! Stage E-LABELS-2: two labels and eight control codes for the E1 self-assessment. Additive only; existing labels, kinds, controls and
//! signatures unchanged. crypto_inventory and log_integrity_check are evidence.control_check labels. The control codes are names only
//! (no framework text is reproduced anywhere).
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
        total: 8,
        passed: 8,
        flagged: 0,
        detail: "hosts=8|cbom=sha256:aaaa",
        run_id: "e1-crypto-inventory",
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
const NEW_LABELS: [LabelCode; 2] = [LabelCode::CryptoInventory, LabelCode::LogIntegrityCheck];
const NEW_CONTROLS: [ControlCode; 8] = [
    ControlCode::PciDss10_3_4,
    ControlCode::PciDss12_3_3,
    ControlCode::DoraRtsArt6,
    ControlCode::DoraRtsArt12,
    ControlCode::Nist80053Au9,
    ControlCode::Nist80053Au10,
    ControlCode::EuAiActArt12,
    ControlCode::EuAiActArt19,
];
const NEW_CONTROL_WORDS: [&str; 8] = [
    "pci_dss_10_3_4",
    "pci_dss_12_3_3",
    "dora_rts_art_6",
    "dora_rts_art_12",
    "nist_800_53_au_9",
    "nist_800_53_au_10",
    "eu_ai_act_art_12",
    "eu_ai_act_art_19",
];

#[test]
fn c1_the_two_labels_are_appended_after_the_triage_labels_in_order() {
    // E-LABELS-3 appends two more labels after these, so they are checked as a contiguous run right after case_outcome.
    let all: Vec<&str> = LabelCode::ALL.iter().map(|l| l.as_str()).collect();
    let at = all.iter().position(|w| *w == "case_outcome").unwrap();
    assert_eq!(
        &all[at..at + 3],
        ["case_outcome", "crypto_inventory", "log_integrity_check"]
    );
    assert_eq!(all[at - 5], "council_decision");
    for w in ["crypto_inventory", "log_integrity_check"] {
        assert!(LabelCode::parse(w).is_some(), "label {w}");
    }
    assert_eq!(LabelCode::parse("crypto_inventories"), None);
}

#[test]
fn c2_the_eight_control_codes_are_appended_after_the_existing_fourteen_in_order() {
    let all: Vec<&str> = ControlCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(all.len(), 22);
    assert_eq!(
        &all[..14],
        [
            "hipaa_164_308_a1",
            "hipaa_164_308_a4",
            "hipaa_164_312_a1",
            "hipaa_164_312_b",
            "hipaa_164_312_c1",
            "hipaa_164_312_d",
            "hipaa_164_312_e1",
            "hitrust_01_access_control",
            "hitrust_06_compliance",
            "hitrust_09_operations",
            "hitrust_10_sdlc",
            "hitrust_13_privacy",
            "policy_p0_data_safety",
            "policy_p3_separation_of_duties"
        ]
    );
    assert_eq!(&all[14..], NEW_CONTROL_WORDS);
    for w in NEW_CONTROL_WORDS {
        assert!(ControlCode::parse(w).is_some(), "control {w}");
    }
    for bad in [
        "pci_dss_10_3_3",
        "nist_800_53_au_11",
        "dora_rts_art_6_x",
        "anything_else",
    ] {
        assert_eq!(ControlCode::parse(bad), None, "{bad}");
    }
}

#[test]
fn c3_the_new_labels_fit_evidence_control_check_and_no_other_kind_and_no_platinum_label() {
    for l in NEW_LABELS {
        for k in KINDS {
            let r = evidence_fields(&rec(k, l, ControlCode::PciDss12_3_3));
            if k == Kind::EvidenceControlCheck {
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
fn c4_every_new_control_works_with_both_new_labels_and_with_an_old_label() {
    for c in NEW_CONTROLS {
        for l in NEW_LABELS {
            must(evidence_fields(&rec(Kind::EvidenceControlCheck, l, c)));
        }
        must(evidence_fields(&rec(
            Kind::EvidenceControlCheck,
            LabelCode::CiTests,
            c,
        )));
    }
}

#[test]
fn c5_existing_labels_and_controls_keep_their_kinds() {
    must(evidence_fields(&rec(
        Kind::EvidenceControlCheck,
        LabelCode::CaseOutcome,
        ControlCode::Hipaa164312b,
    )));
    must(evidence_fields(&rec(
        Kind::EvidenceControlCheck,
        LabelCode::CanaryScan,
        ControlCode::PolicyP0DataSafety,
    )));
    expect_err(evidence_fields(&rec(
        Kind::EvidenceChange,
        LabelCode::CaseOutcome,
        ControlCode::PciDss12_3_3,
    )));
    expect_err(evidence_fields(&rec(
        Kind::EvidencePolicy,
        LabelCode::CiTests,
        ControlCode::Nist80053Au9,
    )));
    for l in [
        LabelCode::NlQuery,
        LabelCode::MlScore,
        LabelCode::RagAnswer,
        LabelCode::ClaimsTriage,
    ] {
        must(platinum_fields(&pd(l)));
    }
}

#[test]
fn c6_the_new_events_sign_encode_and_verify() {
    for c in NEW_CONTROLS {
        for l in NEW_LABELS {
            let f = must(evidence_fields(&rec(Kind::EvidenceControlCheck, l, c)));
            let ev = must(sign_event(&probe(), &f));
            let payload = must(encode_event(&ev));
            assert_eq!(must(verify_event(&payload, &probe().pubkey_hex())), ev);
        }
    }
}

fn say(
    label: LabelCode,
    decision: Decision,
    reason: ReasonCode,
    t: u64,
    p: u64,
    fl: u64,
) -> String {
    let mut r = rec(Kind::EvidenceControlCheck, label, ControlCode::PciDss12_3_3);
    r.decision = decision;
    r.reason = reason;
    (r.total, r.passed, r.flagged) = (t, p, fl);
    plain_english(&must(evidence_fields(&r)))
}

#[test]
fn c7_each_new_label_reads_in_plain_english_with_its_counts_and_without_ids() {
    let inv = say(
        LabelCode::CryptoInventory,
        Decision::Allow,
        ReasonCode::CheckPassed,
        8,
        8,
        0,
    );
    assert!(
        inv.contains("Crypto inventory") && inv.contains("8 hosts"),
        "{inv}"
    );
    let inv2 = say(
        LabelCode::CryptoInventory,
        Decision::Deny,
        ReasonCode::CheckFailed,
        8,
        6,
        2,
    );
    assert!(
        inv2.contains("Crypto inventory") && inv2.contains('2') && inv2 != inv,
        "{inv2}"
    );
    let ok = say(
        LabelCode::LogIntegrityCheck,
        Decision::Allow,
        ReasonCode::CheckPassed,
        1,
        1,
        0,
    );
    assert!(
        ok.contains("Log integrity") && ok.contains("verified"),
        "{ok}"
    );
    let bad = say(
        LabelCode::LogIntegrityCheck,
        Decision::Deny,
        ReasonCode::CheckFailed,
        1,
        0,
        1,
    );
    assert!(
        bad.contains("Log integrity") && bad.contains("failed") && bad != ok,
        "{bad}"
    );
    for s in [&inv, &inv2, &ok, &bad] {
        assert!(
            !s.contains("A control check ran") && !s.contains("sha256") && !s.contains("e1-crypto"),
            "{s}"
        );
    }
}

#[test]
fn c8_the_control_titles_are_names_only_short_distinct_and_say_which_standard() {
    let want = [
        (ControlCode::PciDss10_3_4, "PCI DSS 10.3.4"),
        (ControlCode::PciDss12_3_3, "PCI DSS 12.3.3"),
        (ControlCode::DoraRtsArt6, "DORA RTS Art. 6"),
        (ControlCode::DoraRtsArt12, "DORA RTS Art. 12"),
        (ControlCode::Nist80053Au9, "NIST SP 800-53 AU-9"),
        (ControlCode::Nist80053Au10, "NIST SP 800-53 AU-10"),
        (ControlCode::EuAiActArt12, "EU AI Act Art. 12"),
        (ControlCode::EuAiActArt19, "EU AI Act Art. 19"),
    ];
    let mut titles = Vec::new();
    for (c, t) in want {
        assert_eq!(c.title(), t);
        assert!(c.title().len() < 40);
        titles.push(c.title());
    }
    titles.sort();
    titles.dedup();
    assert_eq!(titles.len(), 8);
}
