//! AT3 latency (release, run with --ignored): request, approve and activate with real tokens and the real in-memory stores against a null sink (the ledger append cost is AT2b's measured limit).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::change::{Change, ChangeControl, MemoryPending, MemoryVersions};
use entropa_tiers::{OfflineVerifier, RecordSink, TierRecord};
use entropa_tokens::{empty_revocations, issue_a, Claims, Tier, Trust};
use std::time::Instant;

struct Null;
impl RecordSink for Null {
    fn write(&self, _: &TierRecord) -> Result<(), String> {
        Ok(())
    }
}
#[test]
#[ignore]
fn change_control_call_latency() {
    const NOW: u64 = 1_800_000_000;
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    trust.add(&issuer.pubkey_hex());
    let v = OfflineVerifier {
        trust,
        audience: "node-1".into(),
        skew: 30,
        max_ttl: 7200,
        rev_max_age: 300,
        revocations: Some(empty_revocations(&issuer, NOW)),
    };
    let tok = |id: u64, s: &str| {
        issue_a(
            &issuer,
            &Claims {
                token_id: format!("{id:032x}"),
                subject: s.into(),
                tier: Tier::T3,
                corpora: vec!["1".repeat(64)],
                actions: vec!["change:prompt".into()],
                spend_cap: 1,
                rate_cap: 1,
                not_before: NOW - 10,
                expiry: NOW + 6000,
                audience: "node-1".into(),
                parent: None,
            },
        )
        .unwrap()
    };
    let (ta, tb) = (tok(1, "a"), tok(2, "b"));
    let (mut rq, mut ap, mut ac) = (vec![], vec![], vec![]);
    for i in 0..2000u64 {
        let (pending, versions) = (MemoryPending::default(), MemoryVersions::default());
        let cc = ChangeControl {
            verifier: &v,
            pending: &pending,
            versions: &versions,
            sink: &Null,
        };
        let c = Change {
            class: "prompt".into(),
            name: format!("n{i}"),
            content_hash: "1".repeat(64),
            parent: None,
        };
        let t = Instant::now();
        let h = cc.request(&ta, None, &c, NOW).unwrap();
        rq.push(t.elapsed().as_nanos());
        let t = Instant::now();
        cc.approve(&tb, None, &h, NOW + 1).unwrap();
        ap.push(t.elapsed().as_nanos());
        let t = Instant::now();
        cc.activate(&ta, None, &h, NOW + 2).unwrap();
        ac.push(t.elapsed().as_nanos());
    }
    for (n, mut x) in [("request", rq), ("approve", ap), ("activate", ac)] {
        x.sort_unstable();
        eprintln!(
            "{n}: p50 {:.3} ms p95 {:.3} ms",
            x[1000] as f64 / 1e6,
            x[1900] as f64 / 1e6
        );
    }
}
