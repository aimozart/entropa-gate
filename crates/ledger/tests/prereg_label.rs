//! TH1 anchoring: one additive label, `prereg_committed`, on evidence.change (a pre-registration record was committed to a ledger). Existing labels, kinds, controls
//! and signatures are unchanged. The anchor record carries only a hash (the detail is hashed and dropped).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_ledger::*;

fn rec(kind: Kind) -> EvidenceRecord<'static> {
    EvidenceRecord {
        kind,
        label: LabelCode::PreregCommitted,
        decision: Decision::Info,
        reason: ReasonCode::None,
        control: ControlCode::Hitrust10Sdlc,
        total: 1,
        passed: 1,
        flagged: 0,
        detail: "entropa-prereg-v1|aaaa",
        run_id: "prereg-aaaa",
        ts: 1_700_000_000,
        key_id: "0123456789abcdef".into(),
    }
}

#[test]
fn l1_the_label_is_the_last_one_and_parses() {
    assert_eq!(LabelCode::ALL.last().unwrap().as_str(), "prereg_committed");
    assert_eq!(
        LabelCode::parse("prereg_committed"),
        Some(LabelCode::PreregCommitted)
    );
}

#[test]
fn l2_it_fits_evidence_change_and_no_other_kind() {
    assert!(evidence_fields(&rec(Kind::EvidenceChange)).is_ok());
    for k in [
        Kind::EvidencePipelineRun,
        Kind::EvidenceControlCheck,
        Kind::EvidenceAccess,
        Kind::EvidencePolicy,
    ] {
        assert!(evidence_fields(&rec(k)).is_err(), "{k:?}");
    }
}

#[test]
fn l3_the_plain_english_sentence_says_what_it_is() {
    let f = evidence_fields(&rec(Kind::EvidenceChange)).unwrap();
    let t = plain_english(&f);
    assert!(t.to_lowercase().contains("pre-registration"), "{t}");
    assert!(
        !t.contains("An event was recorded"),
        "the generic fallback is not enough: {t}"
    );
}

#[test]
fn l4_the_subject_hash_is_blake3_of_the_framed_detail_and_run_id() {
    // the documented formula: BLAKE3("entropa-evidence-subject-v1" 0x00 || len(detail) be64 || detail || len(run_id) be64 || run_id)
    let r = rec(Kind::EvidenceChange);
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-evidence-subject-v1\0");
    for part in [r.detail.as_bytes(), r.run_id.as_bytes()] {
        h.update(&(part.len() as u64).to_be_bytes());
        h.update(part);
    }
    assert_eq!(
        evidence_fields(&r).unwrap().subject_hash,
        hex::encode(h.finalize().as_bytes())
    );
}
