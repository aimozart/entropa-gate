//! AT2b task 5: what the real parts cost. Release profile, run with `--ignored` (a debug build is not a measurement). Reports, never asserts a speed claim except the stated
//! ordering: the append cost of the ledger sink at 1, 300 and 3,000 records (the sink replays the whole ledger on every append: O(n^2), a stated limit), and the decision latency
//! of the gate with the real egress guard, Cedar and meter against a null sink (the ledger excluded).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::adapters::{EgressAdapter, LedgerSink, MemoryMeter, SealedRetrieval};
use entropa_tiers::cedar::CedarPolicy;
use entropa_tiers::{Gate, OfflineVerifier, RecordSink, Request, TierRecord};
use entropa_tokens::{empty_revocations, issue_a, Claims, Tier, Trust};
use std::time::Instant;

const NOW: u64 = 1_800_000_000;
const CORPUS: &str = "00000000000000000000000000000000000000000000000000000000000000aa";

fn rec(i: u64) -> TierRecord {
    TierRecord {
        label: "token_used",
        decision: "allowed",
        reason: "allowed".into(),
        tier: Some("T1"),
        action: "call_model",
        token_hash: Some("a".repeat(64)),
        request_hash: format!("{i:064x}"),
        policy_hash: "c".repeat(64),
        ts: NOW,
    }
}

#[test]
#[ignore]
fn append_latency_at_1_300_and_3000_records() {
    let dir = std::env::temp_dir().join(format!("at2b-lat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let seed = hex::encode(blake3::hash(b"at2b-latency-key").as_bytes());
    let sink = LedgerSink::new(dir, Box::new(Probe::from_signing_key_hex(&seed).unwrap()));
    let mut line = String::new();
    for n in 1..=3000u64 {
        let t = Instant::now();
        sink.write(&rec(n)).unwrap();
        let us = t.elapsed().as_micros();
        if n == 1 || n == 300 || n == 3000 {
            line.push_str(&format!("append #{n}: {us} us\n"));
        }
    }
    eprintln!("{line}");
}

#[test]
#[ignore]
fn decision_latency_real_parts_without_the_ledger() {
    struct Null;
    impl RecordSink for Null {
        fn write(&self, _: &TierRecord) -> Result<(), String> {
            Ok(())
        }
    }
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    trust.add(&issuer.pubkey_hex());
    let v = OfflineVerifier {
        trust,
        audience: "node-1".into(),
        skew: 30,
        max_ttl: 3600,
        rev_max_age: 300,
        revocations: Some(empty_revocations(&issuer, NOW)),
    };
    let eg = EgressAdapter::new(
        entropa_egress::eval::load_policy(&entropa_egress::eval::policy_from_extra(
            &serde_json::json!({}),
        ))
        .unwrap(),
        "https://api.model.example/v1/chat",
        b"k",
    );
    let ret = SealedRetrieval::new(entropa_standards::retrieve::Retriever::from_clauses(
        "v1",
        CORPUS,
        vec![],
    ));
    let pol = CedarPolicy::tiers();
    let meter = MemoryMeter::new();
    let gate = Gate {
        verifier: &v,
        policy: &pol,
        egress: &eg,
        retrieval: &ret,
        meter: &meter,
        sink: &Null,
    };
    let c = Claims {
        token_id: format!("{:032x}", 1),
        subject: "s".into(),
        tier: Tier::T1,
        corpora: vec![CORPUS.into()],
        actions: vec!["call_model".into(), "read_corpus".into()],
        spend_cap: u64::MAX,
        rate_cap: u64::MAX,
        not_before: NOW - 10,
        expiry: NOW + 600,
        audience: "node-1".into(),
        parent: None,
    };
    let tok = issue_a(&issuer, &c).unwrap();
    let mut allow = vec![];
    let mut deny = vec![];
    for i in 0..2000u64 {
        let ok = Request {
            token: tok.clone(),
            action: "call_model".into(),
            cost: 1,
            payload: format!("Summarise the retention rules, item {i}.").into_bytes(),
            ..Request::default()
        };
        let t = Instant::now();
        let o = gate.decide(&ok, NOW);
        allow.push(t.elapsed().as_nanos());
        assert_eq!(o.decision, entropa_tiers::Decision::Allowed);
        let bad = Request {
            action: "call_tool".into(),
            ..ok
        };
        let t = Instant::now();
        let _ = gate.decide(&bad, NOW);
        deny.push(t.elapsed().as_nanos());
    }
    allow.sort_unstable();
    deny.sort_unstable();
    let p = |v: &Vec<u128>, q: usize| v[v.len() * q / 100] as f64 / 1e6;
    eprintln!(
        "allow p50 {:.3} ms p95 {:.3} ms; deny p50 {:.3} ms p95 {:.3} ms",
        p(&allow, 50),
        p(&allow, 95),
        p(&deny, 50),
        p(&deny, 95)
    );
}
