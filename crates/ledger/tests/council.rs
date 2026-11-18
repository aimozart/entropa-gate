//! Council steps as ledger events (stage C1). Hash-only: the reviewed text is hashed and dropped.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use entropa_ledger::*;

fn key_id() -> String {
    "0123456789abcdef".to_string()
}

fn step<'a>(
    label: LabelCode,
    who: Handle,
    decision: Decision,
    reason: ReasonCode,
    text: &'a str,
) -> CouncilStep<'a> {
    CouncilStep {
        label,
        actor: who,
        decision,
        reason,
        subject: text,
        session_id: "council-2026-w45",
        model: None,
        ts: START,
        key_id: key_id(),
    }
}

#[test]
fn c1_the_vocabulary_grows_at_the_end_only() {
    assert_eq!(Kind::parse("council.step"), Some(Kind::CouncilStep));
    let pos = |k: Kind| Kind::ALL.iter().position(|x| *x == k).unwrap();
    assert!(
        pos(Kind::EvidencePolicy) < pos(Kind::CouncilStep),
        "appended after the evidence kinds"
    );
    for w in [
        "council_session",
        "council_packet",
        "council_finding",
        "council_rebuttal",
        "council_decision",
    ] {
        assert!(LabelCode::parse(w).is_some(), "label {w}");
    }
    for w in [
        "council_accepted",
        "council_rejected",
        "council_deferred",
        "council_no_quorum",
    ] {
        assert!(ReasonCode::parse(w).is_some(), "reason {w}");
    }
    for w in [
        "critic-agent",
        "contestor-agent",
        "observer-agent",
        "scheduler-agent",
    ] {
        assert!(Handle::parse(w).is_some(), "handle {w}");
    }
    assert!(Provider::parse("azure").is_some());
}

#[test]
fn c2_fields_carry_the_actor_and_a_subject_hash_only() {
    let f = must(council_fields(&step(
        LabelCode::CouncilFinding,
        Handle::CriticAgent,
        Decision::Info,
        ReasonCode::None,
        "claim 12 was denied without a reason",
    )));
    assert_eq!(f.kind, Kind::CouncilStep);
    assert_eq!(f.handle, Handle::CriticAgent);
    assert_eq!(f.label, LabelCode::CouncilFinding);
    assert_eq!(f.subject_hash.len(), 64);
    assert!(f.agent.is_none() && f.evidence.is_none());
}

#[test]
fn c3_the_same_text_in_two_sessions_hashes_differently() {
    let a = must(council_fields(&step(
        LabelCode::CouncilFinding,
        Handle::CriticAgent,
        Decision::Info,
        ReasonCode::None,
        "x",
    )));
    let mut s = step(
        LabelCode::CouncilFinding,
        Handle::CriticAgent,
        Decision::Info,
        ReasonCode::None,
        "x",
    );
    s.session_id = "council-2026-w46";
    let b = must(council_fields(&s));
    assert_ne!(a.subject_hash, b.subject_hash);
}

#[test]
fn c4_refuses_a_non_council_label_a_bad_session_id_and_identifier_shapes() {
    let bad_label = step(
        LabelCode::NlQuery,
        Handle::CriticAgent,
        Decision::Info,
        ReasonCode::None,
        "x",
    );
    assert!(council_fields(&bad_label).is_err());
    let mut bad_id = step(
        LabelCode::CouncilFinding,
        Handle::CriticAgent,
        Decision::Info,
        ReasonCode::None,
        "x",
    );
    bad_id.session_id = "has spaces";
    assert!(council_fields(&bad_id).is_err());
    let ssn = format!("patient {}-{}-{}", 123, 45, 6789);
    let leak = step(
        LabelCode::CouncilFinding,
        Handle::CriticAgent,
        Decision::Info,
        ReasonCode::None,
        &ssn,
    );
    assert!(council_fields(&leak).is_err());
}

#[test]
fn c5_a_signed_council_event_round_trips_and_describes_itself_in_plain_english() {
    let p = Probe::from_signing_key_hex(&"ab".repeat(32)).unwrap();
    let f = must(council_fields(&step(
        LabelCode::CouncilDecision,
        Handle::HumanPrincipal,
        Decision::Allow,
        ReasonCode::CouncilAccepted,
        "accept finding 1",
    )));
    let ev = must(sign_event(&p, &f));
    let payload = must(encode_event(&ev));
    assert!(!payload.contains("accept finding"));
    let back = must(verify_event(&payload, &p.pubkey_hex()));
    assert_eq!(back.fields, f);
    let text = plain_english(&f);
    assert!(
        text.contains("council") || text.contains("Council"),
        "{text}"
    );
    assert!(text.to_lowercase().contains("accepted"), "{text}");
}

#[test]
fn c6_every_council_label_has_its_own_sentence() {
    let mut seen = std::collections::HashSet::new();
    for (label, who, dec, why) in [
        (
            LabelCode::CouncilSession,
            Handle::SchedulerAgent,
            Decision::Info,
            ReasonCode::None,
        ),
        (
            LabelCode::CouncilPacket,
            Handle::OrchestratorAgent,
            Decision::Info,
            ReasonCode::None,
        ),
        (
            LabelCode::CouncilFinding,
            Handle::CriticAgent,
            Decision::Info,
            ReasonCode::None,
        ),
        (
            LabelCode::CouncilRebuttal,
            Handle::ContestorAgent,
            Decision::Info,
            ReasonCode::None,
        ),
        (
            LabelCode::CouncilDecision,
            Handle::HumanPrincipal,
            Decision::Deny,
            ReasonCode::CouncilRejected,
        ),
        (
            LabelCode::CouncilDecision,
            Handle::HumanPrincipal,
            Decision::Hold,
            ReasonCode::CouncilDeferred,
        ),
        (
            LabelCode::CouncilSession,
            Handle::SchedulerAgent,
            Decision::Hold,
            ReasonCode::CouncilNoQuorum,
        ),
    ] {
        let f = must(council_fields(&step(label, who, dec, why, "t")));
        assert!(
            seen.insert(plain_english(&f)),
            "duplicate sentence for {label:?} {dec:?}"
        );
    }
}
