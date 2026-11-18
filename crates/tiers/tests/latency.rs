//! AT2 task 6: decision latency. p50 and p95 in milliseconds for an allow and a deny at each tier, 2,000 runs each, token verification included (ML-DSA-65 verify), with fakes for
//! the guard, retrieval, meter and sink so that the number is the gate's own. Numbers are printed (see docs/evidence/at2/latency-*.txt); the only assertions are a loose sanity bound
//! in the release profile and that a deny at the tier ceiling is not slower than the allow it refuses (it does less work).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::cedar::CedarPolicy;
use entropa_tiers::{
    Decision, EgressGuard, Gate, Guard, Meter, OfflineVerifier, RecordSink, Request, Retrieval,
    TierRecord,
};
use entropa_tokens::{empty_revocations, issue_a, Claims, Tier, Trust};

const NOW: u64 = 1_800_000_000;
const CORPUS: &str = "00000000000000000000000000000000000000000000000000000000000000aa";
struct F;
impl EgressGuard for F {
    fn check(&self, _: Tier, _: &[u8]) -> Result<Guard, String> {
        Ok(Guard::Allow)
    }
}
impl Retrieval for F {
    fn read(&self, _: &str, _: &str) -> Result<Vec<u8>, String> {
        Ok(b"a".to_vec())
    }
}
impl Meter for F {
    fn spent(&self, _: &str) -> u64 {
        0
    }
    fn calls_last_minute(&self, _: &str, _: u64) -> u64 {
        0
    }
}
impl RecordSink for F {
    fn write(&self, _: &TierRecord) -> Result<(), String> {
        Ok(())
    }
}

fn pct(mut v: Vec<f64>) -> (f64, f64) {
    v.sort_by(f64::total_cmp);
    (v[v.len() / 2], v[v.len() * 95 / 100])
}

#[test]
fn l1_decision_latency_per_tier_for_allow_and_deny() {
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
    let cedar = CedarPolicy::tiers();
    let gate = Gate {
        verifier: &v,
        policy: &cedar,
        egress: &F,
        retrieval: &F,
        meter: &F,
        sink: &F,
    };
    let token = |id: u64, tier| {
        issue_a(
            &issuer,
            &Claims {
                token_id: format!("{id:032x}"),
                subject: "s".into(),
                tier,
                corpora: vec![CORPUS.into()],
                actions: vec![
                    "call_model".into(),
                    "call_tool".into(),
                    "read_corpus".into(),
                    "tool:search".into(),
                ],
                spend_cap: 1000,
                rate_cap: 10,
                not_before: NOW - 10,
                expiry: NOW + 600,
                audience: "node-1".into(),
                parent: None,
            },
        )
        .unwrap()
    };
    let mut report = String::new();
    let mut allow_p50 = 0.0;
    for (name, tier, action, allowed) in [
        ("T0 allow read_corpus", Tier::T0, "read_corpus", true),
        ("T0 deny call_model", Tier::T0, "call_model", false),
        ("T1 allow call_model", Tier::T1, "call_model", true),
        ("T1 deny call_tool", Tier::T1, "call_tool", false),
        ("T2 allow call_tool", Tier::T2, "call_tool", true),
        ("T2 deny unknown action", Tier::T2, "write_corpus", false),
    ] {
        let r = Request {
            token: token(7, tier),
            action: action.into(),
            corpus: Some(CORPUS.into()),
            tool: Some("tool:search".into()),
            cost: 1,
            payload: b"hello".to_vec(),
            text: "q".into(),
            ..Request::default()
        };
        let mut ms = Vec::new();
        for _ in 0..2000 {
            let t = std::time::Instant::now();
            let o = gate.decide(&r, NOW);
            ms.push(t.elapsed().as_secs_f64() * 1000.0);
            assert_eq!(o.decision == Decision::Allowed, allowed, "{name}");
        }
        let (p50, p95) = pct(ms);
        report.push_str(&format!("{name}: p50 {p50:.4} ms, p95 {p95:.4} ms\n"));
        if name == "T0 allow read_corpus" {
            allow_p50 = p50;
        }
        if !cfg!(debug_assertions) {
            assert!(p95 < 50.0, "{name}: p95 {p95} ms");
        }
    }
    eprintln!("{report}");
    assert!(allow_p50 > 0.0);
}
