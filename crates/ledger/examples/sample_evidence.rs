#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
//! Prints one synthetic evidence event signed with a public demo key (for the specification).
use entropa_core::Probe;
use entropa_ledger::*;
fn main() {
    let probe = Probe::from_signing_key_hex(&"5c".repeat(32)).unwrap();
    let key_id = entropa_approvals::key_id(&probe.pubkey_hex());
    let rec = EvidenceRecord {
        kind: Kind::EvidencePipelineRun,
        label: LabelCode::Silver,
        decision: Decision::Allow,
        reason: ReasonCode::CheckPassed,
        control: ControlCode::Hipaa164312c1,
        total: 7000,
        passed: 6210,
        flagged: 790,
        detail: "synthetic example: night=2026-11-05 layer=silver valid+quarantine=input",
        run_id: "run-2026-11-05-s",
        ts: 1_793_000_000,
        key_id,
    };
    let f = evidence_fields(&rec).unwrap();
    let ev = sign_event(&probe, &f).unwrap();
    let payload = encode_event(&ev).unwrap();
    // pretty print without the (very long) signature
    let mut v: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let sig = v["sig"].as_str().unwrap().to_string();
    v["sig"] = serde_json::Value::String(format!(
        "{}...({} hex characters, ML-DSA-65)",
        &sig[..32],
        sig.len()
    ));
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
    println!(
        "PUBKEY {}",
        probe.pubkey_hex().chars().take(48).collect::<String>()
    );
}
