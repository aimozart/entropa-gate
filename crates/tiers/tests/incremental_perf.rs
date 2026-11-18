//! LEDGER-INCREMENTAL latency bar (release, run with --ignored): p95 of the append latency over the first 1,000, around 3,000 and over the LAST 1,000 of 30,000 appends; the last window must be
//! within 3x of the first. Real signer, real files.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_ledger::{
    evidence_fields, ControlCode, Decision, EvidenceRecord, Kind, LabelCode, ReasonCode,
};
use entropa_tiers::append::IncrementalLedger;

#[test]
#[ignore]
fn p95_over_30000_appends_stays_within_3x_of_the_first_thousand() {
    let d = std::env::temp_dir().join(format!("inc-perf2-{}", std::process::id()));
    std::fs::create_dir_all(d.join("evidence-ledger")).unwrap();
    let p =
        Probe::from_signing_key_hex(&hex::encode(blake3::hash(b"inc-perf2").as_bytes())).unwrap();
    let kid = entropa_approvals::key_id(&p.pubkey_hex());
    let w = IncrementalLedger::new(d, Box::new(p));
    let mut lat = Vec::with_capacity(30_000);
    for i in 0..30_000u64 {
        let detail = format!("d{i}");
        let run = format!("{i:064x}");
        let f = evidence_fields(&EvidenceRecord {
            kind: Kind::parse("evidence.policy").unwrap(),
            label: LabelCode::parse("policy_verdict").unwrap(),
            decision: Decision::Allow,
            reason: ReasonCode::parse("within_limits").unwrap(),
            control: ControlCode::parse("hitrust_01_access_control").unwrap(),
            total: 1,
            passed: 1,
            flagged: 0,
            detail: &detail,
            run_id: &run,
            ts: 1_800_000_000 + i,
            key_id: kid.clone(),
        })
        .unwrap();
        let t = std::time::Instant::now();
        w.append_event(&f).unwrap();
        lat.push(t.elapsed().as_micros() as f64);
    }
    let p95 = |s: &[f64]| {
        let mut v = s.to_vec();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() * 95 / 100]
    };
    let (first, mid, last) = (
        p95(&lat[..1000]),
        p95(&lat[2500..3500]),
        p95(&lat[29_000..]),
    );
    eprintln!("p95 first 1000: {first:.0} us; around 3000: {mid:.0} us; last 1000 of 30000: {last:.0} us; ratio {:.2}", last / first);
    assert!(
        last <= 3.0 * first,
        "the append cost grew: {first} -> {last}"
    );
}
