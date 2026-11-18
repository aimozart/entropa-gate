//! NODECORE pin for copy C (a stage record (not published) step 1): the incremental writer (`IncrementalLedger`) and the platinum evidence writer (`log_evidence_with`, copy A) write
//! IDENTICAL bytes (`records.log`, `checkpoints.log`) for the same five records and the same key. Green on the unmoved code, by design: it fixes today's behaviour before a move.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_ledger::{
    evidence_fields, ControlCode, Decision, EvidenceRecord, Kind, LabelCode, ReasonCode,
};
use entropa_tiers::append::IncrementalLedger;

fn probe() -> Probe {
    Probe::from_signing_key_hex(&format!("{:02x}", 9u8).repeat(32)).unwrap()
}

#[test]
fn c1_the_incremental_writer_and_platinum_write_the_same_evidence_ledger_bytes() {
    let root = std::env::temp_dir().join(format!("nodecore-pin-c-{}", std::process::id()));
    let (a, c) = (root.join("a"), root.join("c"));
    for d in [&a, &c] {
        std::fs::create_dir_all(d.join("evidence-ledger")).unwrap();
    }
    let p = probe();
    let key_id = entropa_approvals::key_id(&p.pubkey_hex());
    let w = IncrementalLedger::new(c.clone(), Box::new(probe()));
    for i in 1..=5u64 {
        let run = format!("{i:064x}");
        let detail = format!("detail-{i}");
        let (dec, dec_s) = if i % 2 == 0 {
            (Decision::Allow, "allow")
        } else {
            (Decision::Deny, "deny")
        };
        let req = format!(
            r#"{{"kind":"evidence.policy","label":"policy_verdict","decision":"{dec_s}","reason":"within_limits","control":"hitrust_01_access_control","total":1,"passed":{},"flagged":0,"detail":"{detail}","run_id":"{run}","ts":{}}}"#,
            i % 2,
            1_800_000_000 + i
        );
        entropa_platinum::log_evidence_with(&a, &p, &req).unwrap();
        let f = evidence_fields(&EvidenceRecord {
            kind: Kind::parse("evidence.policy").unwrap(),
            label: LabelCode::parse("policy_verdict").unwrap(),
            decision: dec,
            reason: ReasonCode::parse("within_limits").unwrap(),
            control: ControlCode::parse("hitrust_01_access_control").unwrap(),
            total: 1,
            passed: i % 2,
            flagged: 0,
            detail: &detail,
            run_id: &run,
            ts: 1_800_000_000 + i,
            key_id: key_id.clone(),
        })
        .unwrap();
        w.append_event(&f).unwrap();
    }
    for f in ["records.log", "checkpoints.log"] {
        let x = std::fs::read(a.join("evidence-ledger").join(f)).unwrap();
        let y = std::fs::read(c.join("evidence-ledger").join(f)).unwrap();
        assert!(!x.is_empty(), "{f} is empty: the test would prove nothing");
        assert_eq!(x, y, "{f} differs between copy A and copy C");
    }
}
