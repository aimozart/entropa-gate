//! Audit-evidence events: pipeline runs, control checks, access decisions, changes and policy events,
//! each tagged with a control code. Data-minimal: counts, codes and a hash, never data. Synthetic only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use entropa_ledger::*;

fn probe() -> Probe {
    Probe::from_signing_key_hex(&"cd".repeat(32)).unwrap()
}

fn rec<'a>(kind: Kind, label: LabelCode) -> EvidenceRecord<'a> {
    EvidenceRecord {
        kind,
        label,
        decision: Decision::Allow,
        reason: ReasonCode::CheckPassed,
        control: ControlCode::Hipaa164312b,
        total: 7000,
        passed: 6210,
        flagged: 790,
        detail: "night=2026-11-05;layer=silver;valid+quarantine=input",
        run_id: "run-2026-11-05-s",
        ts: START,
        key_id: "0123456789abcdef".into(),
    }
}

#[test]
fn x1_the_vocabulary_grows_at_the_end_only() {
    for (w, k) in [
        ("evidence.pipeline_run", Kind::EvidencePipelineRun),
        ("evidence.control_check", Kind::EvidenceControlCheck),
        ("evidence.access", Kind::EvidenceAccess),
        ("evidence.change", Kind::EvidenceChange),
        ("evidence.policy", Kind::EvidencePolicy),
    ] {
        assert_eq!(Kind::parse(w), Some(k));
    }
    // the council kind was appended after the evidence kinds (stage C1); the evidence kinds keep their positions
    assert_eq!(Kind::ALL.last().copied(), Some(Kind::CouncilStep));
    for w in [
        "bronze",
        "silver",
        "gold",
        "platinum",
        "rls_test",
        "masking_check",
        "k_anonymity",
        "canary_scan",
        "identifier_range",
        "secret_scan",
        "ci_tests",
        "table_read",
        "deploy",
        "rollback",
        "schema_change",
        "key_rotation",
        "policy_approved",
        "code_change",
    ] {
        assert!(LabelCode::parse(w).is_some(), "label {w}");
    }
    for w in ["check_passed", "check_failed"] {
        assert!(ReasonCode::parse(w).is_some(), "reason {w}");
    }
    for w in [
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
        "policy_p3_separation_of_duties",
    ] {
        assert!(ControlCode::parse(w).is_some(), "control {w}");
    }
    assert_eq!(ControlCode::parse("anything_else"), None);
}

#[test]
fn x2_fields_carry_the_control_counts_and_a_detail_hash() {
    let f = must(evidence_fields(&rec(
        Kind::EvidencePipelineRun,
        LabelCode::Silver,
    )));
    assert_eq!(f.kind, Kind::EvidencePipelineRun);
    assert_eq!(f.tenant, Tenant::Hippagrchealthcare);
    assert_eq!(f.handle, Handle::AgentHippagrchealthcare);
    let e = f.evidence.clone().unwrap();
    assert_eq!(
        (e.control, e.total, e.passed, e.flagged),
        (ControlCode::Hipaa164312b, 7000, 6210, 790)
    );
    assert_eq!(f.subject_hash.len(), 64);
    assert!(f.agent.is_none());
}

#[test]
fn x3_the_hash_binds_detail_and_run_and_is_framed() {
    let a = must(evidence_fields(&rec(
        Kind::EvidencePipelineRun,
        LabelCode::Silver,
    )))
    .subject_hash;
    let mut r = rec(Kind::EvidencePipelineRun, LabelCode::Silver);
    r.detail = "different";
    assert_ne!(a, must(evidence_fields(&r)).subject_hash);
    let mut r = rec(Kind::EvidencePipelineRun, LabelCode::Silver);
    r.run_id = "run-other";
    assert_ne!(a, must(evidence_fields(&r)).subject_hash);
}

#[test]
fn x4_kind_and_label_must_belong_together() {
    for (k, l) in [
        (Kind::EvidencePipelineRun, LabelCode::RlsTest),
        (Kind::EvidenceControlCheck, LabelCode::Silver),
        (Kind::EvidenceAccess, LabelCode::Deploy),
        (Kind::EvidenceChange, LabelCode::TableRead),
        (Kind::EvidencePolicy, LabelCode::Gold),
        (Kind::AgentInvocation, LabelCode::Silver),
    ] {
        expect_err(evidence_fields(&rec(k, l)));
    }
    must(evidence_fields(&rec(
        Kind::EvidenceControlCheck,
        LabelCode::RlsTest,
    )));
    must(evidence_fields(&rec(
        Kind::EvidenceAccess,
        LabelCode::TableRead,
    )));
    must(evidence_fields(&rec(
        Kind::EvidenceChange,
        LabelCode::KeyRotation,
    )));
    must(evidence_fields(&rec(
        Kind::EvidenceChange,
        LabelCode::CodeChange,
    )));
    must(evidence_fields(&rec(
        Kind::EvidencePolicy,
        LabelCode::PolicyApproved,
    )));
}

#[test]
fn x5_counts_must_be_consistent() {
    let mut r = rec(Kind::EvidencePipelineRun, LabelCode::Silver);
    r.passed = 7001;
    expect_err(evidence_fields(&r));
    r.passed = 10;
    r.flagged = 7001;
    expect_err(evidence_fields(&r));
    r.flagged = 0;
    r.total = 1 << 60;
    expect_err(evidence_fields(&r));
}

#[test]
fn x6_sign_encode_verify_round_trip_and_the_control_is_visible() {
    let f = must(evidence_fields(&rec(
        Kind::EvidencePipelineRun,
        LabelCode::Gold,
    )));
    let ev = must(sign_event(&probe(), &f));
    let payload = must(encode_event(&ev));
    assert!(
        payload.contains("\"control\":\"hipaa_164_312_b\""),
        "{payload}"
    );
    assert!(!payload.contains("valid+quarantine"));
    assert_eq!(must(verify_event(&payload, &probe().pubkey_hex())), ev);
    lower_crew_free(&payload);
}

#[test]
fn x7_the_decoder_keeps_evidence_and_kind_in_step() {
    let f = must(evidence_fields(&rec(
        Kind::EvidencePipelineRun,
        LabelCode::Silver,
    )));
    let payload = must(encode_event(&must(sign_event(&probe(), &f))));
    // an evidence kind without evidence, and evidence on another kind, are both refused
    let no_ev = payload.replace("\"evidence\":", "\"evidenceX\":");
    expect_err(decode_event(&no_ev));
    let wrong_kind = payload.replace("evidence.pipeline_run", "tx.screened");
    expect_err(decode_event(&wrong_kind));
    let bad_control = payload.replace("hipaa_164_312_b", "made_up");
    expect_err(decode_event(&bad_control));
}

#[test]
fn x8_text_with_a_valid_range_identifier_shape_is_refused() {
    let mut r = rec(Kind::EvidencePipelineRun, LabelCode::Silver);
    let ssn = format!("patient {}-{}-{}", "123", "45", "6789");
    r.detail = &ssn;
    expect_err(evidence_fields(&r));
    r.detail = "patient 900-00-0001";
    must(evidence_fields(&r));
}

#[test]
fn x9_existing_events_are_byte_for_byte_unchanged() {
    // an event without evidence must not mention the new key at all (golden vectors stay valid)
    let f = sample_fields(&probe());
    let payload = must(encode_event(&must(sign_event(&probe(), &f))));
    assert!(!payload.contains("evidence"));
}
