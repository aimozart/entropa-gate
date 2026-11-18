//! Platinum AI decisions as ledger events (stage P1). All data is synthetic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use entropa_ledger::*;

const QUESTION: &str = "How many claims were denied last month by payer?";
const SQL: &str = "SELECT payer, COUNT(*) FROM platinum.denials GROUP BY payer LIMIT 100";

fn probe() -> Probe {
    Probe::from_signing_key_hex(&"ab".repeat(32)).unwrap()
}

fn key_id() -> String {
    "0123456789abcdef".to_string()
}

fn meta() -> AgentMeta {
    AgentMeta {
        provider: Provider::Vertex,
        model_id: "gemini-3.8-flash".into(),
        input_tokens: 120,
        output_tokens: 40,
        cost_micro_usd: 90,
    }
}

fn decision<'a>(input: &'a str, output: &'a str) -> PlatinumDecision<'a> {
    PlatinumDecision {
        label: LabelCode::NlQuery,
        decision: Decision::Allow,
        reason: ReasonCode::GuardPassed,
        input,
        output,
        run_id: "run-2026-11-05-s",
        model: meta(),
        ts: START,
        key_id: key_id(),
    }
}

#[test]
fn p1_the_vocabulary_grows_at_the_end_only() {
    assert_eq!(
        Kind::parse("platinum.decision"),
        Some(Kind::PlatinumDecision)
    );
    let pos = |k: Kind| Kind::ALL.iter().position(|x| *x == k).unwrap();
    assert!(
        pos(Kind::PlatinumDecision) < pos(Kind::EvidencePipelineRun),
        "new kinds are appended after it"
    );
    for w in ["nl_query", "ml_score", "rag_answer"] {
        assert!(LabelCode::parse(w).is_some(), "label {w}");
    }
    for w in ["guard_passed", "guard_refused", "injection_suspected"] {
        assert!(ReasonCode::parse(w).is_some(), "reason {w}");
    }
    for w in ["local", "sparkml"] {
        assert!(Provider::parse(w).is_some(), "provider {w}");
    }
}

#[test]
fn p2_fields_are_for_the_clinic_agent_and_the_platinum_kind() {
    let f = must(platinum_fields(&decision(QUESTION, SQL)));
    assert_eq!(f.kind, Kind::PlatinumDecision);
    assert_eq!(f.tenant, Tenant::Hippagrchealthcare);
    assert_eq!(f.handle, Handle::AgentHippagrchealthcare);
    assert_eq!(f.label, LabelCode::NlQuery);
    assert_eq!(f.subject_hash.len(), 64);
    assert!(f
        .subject_hash
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert_eq!(f.agent, Some(meta()));
}

#[test]
fn p3_the_hash_is_deterministic_and_binds_input_output_and_run() {
    let a = must(platinum_fields(&decision(QUESTION, SQL))).subject_hash;
    assert_eq!(
        a,
        must(platinum_fields(&decision(QUESTION, SQL))).subject_hash
    );
    assert_ne!(
        a,
        must(platinum_fields(&decision("other question", SQL))).subject_hash
    );
    assert_ne!(
        a,
        must(platinum_fields(&decision(QUESTION, "SELECT 1"))).subject_hash
    );
    let mut d = decision(QUESTION, SQL);
    d.run_id = "run-2026-11-06-s";
    assert_ne!(a, must(platinum_fields(&d)).subject_hash);
    // moving a byte from input to output must change the hash (length framing)
    assert_ne!(
        must(platinum_fields(&decision("ab", "c"))).subject_hash,
        must(platinum_fields(&decision("a", "bc"))).subject_hash
    );
}

#[test]
fn p4_the_signed_payload_never_carries_the_raw_text() {
    let f = must(platinum_fields(&decision(QUESTION, SQL)));
    let ev = must(sign_event(&probe(), &f));
    let payload = must(encode_event(&ev));
    assert!(!payload.contains("denied"));
    assert!(!payload.contains("SELECT"));
    assert!(!payload.contains("platinum.denials"));
    assert_eq!(must(verify_event(&payload, &probe().pubkey_hex())), ev);
    lower_crew_free(&payload);
}

#[test]
fn p5_bad_inputs_are_refused_without_echoing_them() {
    let mut d = decision(QUESTION, SQL);
    d.run_id = "";
    expect_err(platinum_fields(&d));
    d.run_id = "has space";
    let e = expect_err(platinum_fields(&d));
    assert!(!format!("{e:?}").contains("has space"));
    d.run_id = "run-1";
    d.key_id = "NOTHEX".into();
    expect_err(platinum_fields(&d));
    d.key_id = key_id();
    d.label = LabelCode::FraudScreen; // not a platinum label
    expect_err(platinum_fields(&d));
    let big = "x".repeat(2 * 1024 * 1024);
    expect_err(platinum_fields(&decision(&big, SQL)));
}

#[test]
fn p6_a_synthetic_ssn_shape_in_the_input_is_refused() {
    // P0: valid-range identifier shapes must never be hashed into a decision silently.
    let ssn = format!("{}-{}-{}", "123", "45", "6789");
    expect_err(platinum_fields(&decision(&ssn, SQL)));
    // the reserved invalid range is allowed (it can never match a real person)
    must(platinum_fields(&decision("patient 900-00-0001", SQL)));
}
