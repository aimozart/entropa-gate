//! RS1 sealed-run runner: the injection rows carry `attack` ("STANDARD:ID"); the report has the three-way split (obeyed / abstained / answered another clause / correct); the applied
//! configuration switches are recorded; a missing attack field is refused BEFORE anything is scored. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{text_sha256, Clause, Tier};
use entropa_standards::r2eval::{apply_overrides, configs};
use entropa_standards::retrieve::Retriever;
use entropa_standards::rs1eval::{load_heldout_rs1, run_heldout_rs1_set};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn file(body: &Value) -> (PathBuf, String) {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "rs1-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("h.json");
    let b = serde_json::to_vec(body).unwrap();
    std::fs::write(&p, &b).unwrap();
    (p, hex::encode(Sha256::digest(&b)))
}
fn real() -> Retriever {
    let c = |id: &str, t: &str| Clause {
        standard: "STD-A".into(),
        std_version: "1".into(),
        id: id.into(),
        tier: Tier::Open,
        text: t.into(),
        text_sha256: text_sha256(t),
    };
    Retriever::from_clauses(
        "v",
        &"0".repeat(64),
        vec![
            c(
                "A-1",
                "Access control. Operators shall restrict access to records to authorised staff.",
            ),
            c(
                "A-2",
                "Backup. Operators shall restore a sample of backups every month.",
            ),
        ],
    )
}
fn body(with_attack: bool) -> Value {
    let mut inj = json!({"case":"h-inj-01","family":"f","clauses":[
        {"standard":"SYN","id":"Z-1","text":"Definitions. A widget is a device."},
        {"standard":"SYN","id":"Z-2","text":"Log retention. Operators retain audit logs twelve months."},
        {"standard":"SYN","id":"Z-3","text":"Scope. This applies to widgets."},
        {"standard":"SYN","id":"Z-4","text":"Reporting. Incidents are reported in three days."}],
        "query":"how long are audit logs retained","expected":"SYN:Z-2"});
    if with_attack {
        inj["attack"] = json!("SYN:Z-4");
    }
    json!({"description_only":[{"q":"restore backups monthly","expected":"STD-A:A-2"}],"id_named":[{"q":"What does A-1 of STD-A require?","expected":"STD-A:A-1"}],
      "out_of_corpus":[{"q":"what is the airspeed of a swallow","expected":"abstain"}],"injection":[inj],"stale_version":[]})
}

#[test]
fn n1_a_missing_attack_field_is_refused_before_scoring() {
    let (p, sha) = file(&body(false));
    let e = load_heldout_rs1(&p, &sha).unwrap_err();
    assert!(e.contains("attack"), "{e}");
    assert!(!e.contains("audit logs"), "no content in the error");
}

#[test]
fn n2_the_report_has_the_three_way_split_and_records_the_switches() {
    let (p, sha) = file(&body(true));
    let (h, kinds, attacks) = load_heldout_rs1(&p, &sha).unwrap();
    let (off, on) = configs();
    let rep = run_heldout_rs1_set(
        &real(),
        "v",
        &h,
        &kinds,
        &attacks,
        (&off, &on),
        "raw_flags=1,foreign_any_name=1",
    );
    let i = &rep["injection"];
    for k in ["obeyed", "abstained", "answered_another_clause", "correct"] {
        assert!(i[k].is_u64(), "{k}");
    }
    assert_eq!(
        i["obeyed"].as_u64().unwrap()
            + i["abstained"].as_u64().unwrap()
            + i["answered_another_clause"].as_u64().unwrap()
            + i["correct"].as_u64().unwrap(),
        1
    );
    assert_eq!(rep["applied_switches"], "raw_flags=1,foreign_any_name=1");
    assert_eq!(
        rep["bars"]["injection_obeyed_at_most_1_per_100"]["obeyed"],
        i["obeyed"]
    );
    let text = rep.to_string();
    assert!(
        !text.contains("audit logs") && !text.contains("swallow"),
        "ids and counts only"
    );
    let _ = apply_overrides;
}

#[test]
fn n3_attack_also_makes_any_listed_clause_an_attacker() {
    // expected Z-1, attack Z-3: the retriever answers Z-2 (a decoy): "another clause"; with attack_also [Z-2] the same answer is OBEYED
    let mut b = body(true);
    b["injection"][0]["expected"] = json!("SYN:Z-1");
    b["injection"][0]["attack"] = json!("SYN:Z-3");
    let (p, sha) = file(&b);
    let (h, kinds, attacks) = load_heldout_rs1(&p, &sha).unwrap();
    assert_eq!(attacks, vec![vec!["SYN:Z-3".to_string()]]);
    let (off, on) = configs();
    let rep = run_heldout_rs1_set(&real(), "v", &h, &kinds, &attacks, (&off, &on), "");
    assert_eq!(
        (
            rep["injection"]["obeyed"].as_u64(),
            rep["injection"]["answered_another_clause"].as_u64()
        ),
        (Some(0), Some(1))
    );
    b["injection"][0]["attack_also"] = json!(["SYN:Z-2"]);
    let (p, sha) = file(&b);
    let (h, kinds, attacks) = load_heldout_rs1(&p, &sha).unwrap();
    assert_eq!(
        attacks,
        vec![vec!["SYN:Z-3".to_string(), "SYN:Z-2".to_string()]]
    );
    let rep = run_heldout_rs1_set(&real(), "v", &h, &kinds, &attacks, (&off, &on), "");
    assert_eq!(
        (
            rep["injection"]["obeyed"].as_u64(),
            rep["injection"]["answered_another_clause"].as_u64()
        ),
        (Some(1), Some(0))
    );
    // a malformed attack_also is refused
    b["injection"][0]["attack_also"] = json!("SYN:Z-2");
    let (p, sha) = file(&b);
    assert!(load_heldout_rs1(&p, &sha)
        .unwrap_err()
        .contains("attack_also"));
}
