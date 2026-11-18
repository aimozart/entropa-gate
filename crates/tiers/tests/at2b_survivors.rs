//! AT2b mutation triage (tests only): survivors of the first cargo-mutants run on adapters.rs, each killed here and seen to FAIL against its mutant (docs/evidence/at2b/mutation-triage.txt).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::transparency_log::decode_record;
use entropa_core::Probe;
use entropa_ledger::{decode_event, FileStore, LedgerStore};
use entropa_tiers::adapters::{LedgerSink, MemoryMeter};
use entropa_tiers::{Meter, RecordSink, TierRecord};

const NOW: u64 = 1_800_000_000;

#[test]
fn s1_a_call_is_counted_up_to_59_seconds_and_gone_at_60() {
    let m = MemoryMeter::new();
    m.try_reserve("t", 0, 10, 10, NOW).unwrap();
    assert_eq!(m.calls_last_minute("t", NOW + 59), 1);
    assert_eq!(
        m.calls_last_minute("t", NOW + 60),
        0,
        "exactly 60 s later it is outside the minute"
    );
}

#[test]
fn s2_release_removes_the_reservation_that_was_made_at_that_time_not_another() {
    let m = MemoryMeter::new();
    m.try_reserve("t", 1, 10, 10, NOW).unwrap();
    m.try_reserve("t", 1, 10, 10, NOW + 30).unwrap();
    m.release("t", 1, NOW);
    // the call at NOW+30 must still be counted at NOW+60 (the NOW one has left the window either way)
    assert_eq!(m.calls_last_minute("t", NOW + 60), 1);
}

fn rec(allow: bool, reason: &str) -> TierRecord {
    TierRecord {
        label: if allow { "token_used" } else { "token_denied" },
        decision: if allow { "allowed" } else { "denied" },
        reason: reason.into(),
        tier: Some("T1"),
        action: "call_model",
        token_hash: Some("a".repeat(64)),
        request_hash: "b".repeat(64),
        policy_hash: "c".repeat(64),
        ts: NOW,
    }
}

/// Write the records and read back (decision, reason, passed, flagged) of each, decoded from the stored events.
fn written(tag: &str, recs: &[TierRecord]) -> Vec<(String, String, u64, u64)> {
    let dir = std::env::temp_dir().join(format!("at2b-surv-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let seed = hex::encode(blake3::hash(format!("at2b-surv-{tag}").as_bytes()).as_bytes());
    let sink = LedgerSink::new(
        dir.clone(),
        Box::new(Probe::from_signing_key_hex(&seed).unwrap()),
    );
    for r in recs {
        sink.write(r).unwrap();
    }
    let store = FileStore::open(&dir.join("evidence-ledger")).unwrap();
    (0..store.len())
        .map(|i| {
            let (payload, _) = decode_record(&store.record(i).unwrap()).unwrap();
            let ev = decode_event(&payload).unwrap();
            let m = ev.fields.evidence.unwrap();
            (
                ev.fields.decision.as_str().to_string(),
                ev.fields.reason.as_str().to_string(),
                m.passed,
                m.flagged,
            )
        })
        .collect()
}

#[test]
fn s3_the_stored_decision_reason_and_counts_follow_the_record() {
    let r = written("s3", &[rec(true, "allowed"), rec(false, "egress_blocked")]);
    assert_eq!(r[0], ("allow".into(), "within_limits".into(), 1, 0));
    assert_eq!(r[1], ("deny".into(), "guard_refused".into(), 0, 1));
}

#[test]
fn s4_each_denial_word_lands_on_its_planned_reason() {
    let policy = [
        "spend_cap",
        "rate_cap",
        "tier_forbids",
        "policy_denied",
        "policy_error",
        "egress_error",
        "retrieval_error",
        "record_failed",
        "internal_error",
    ];
    let gate = [
        "expired",
        "unknown_action",
        "corpus_not_in_token",
        "action_not_in_token",
        "revoked",
        "bad_signature",
    ];
    let mut recs: Vec<TierRecord> = policy.iter().map(|w| rec(false, w)).collect();
    recs.extend(gate.iter().map(|w| rec(false, w)));
    let got = written("s4", &recs);
    for (i, _) in policy.iter().enumerate() {
        assert_eq!(got[i].1, "policy_deny", "{}", policy[i]);
    }
    for (j, w) in gate.iter().enumerate() {
        assert_eq!(got[policy.len() + j].1, "gate_denied", "{w}");
    }
}
