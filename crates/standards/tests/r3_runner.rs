//! R3 runner tests: the DEV3 sets load only with their frozen hashes, the DEV3 report has every block, and the R3 held-out runner is pinned
//! to the sha256 in the order, prints counts and ids only, and judges the bars.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{text_sha256, Clause, Tier};
use entropa_standards::r2eval;
use entropa_standards::r3eval;
use entropa_standards::retrieve::{Config, Retriever};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn dev_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval_dev")
}
fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "r3-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn clause(std: &str, id: &str, text: &str) -> Clause {
    Clause {
        standard: std.into(),
        std_version: "1".into(),
        id: id.into(),
        tier: Tier::Open,
        text: text.into(),
        text_sha256: text_sha256(text),
    }
}
fn real() -> Retriever {
    Retriever::from_clauses(
        "v",
        &"0".repeat(64),
        vec![
            clause("STD-A", "A-1", "Access control. Operators shall restrict access to records to authorised staff and review the access list every quarter."),
            clause("STD-A", "A-2", "Backup. Operators shall restore a sample of backups every month and keep a record of the result."),
        ],
    )
}

#[test]
fn q1_dev3_loads_with_its_frozen_hashes_and_has_the_ordered_sizes() {
    let d = r3eval::load_dev3(&dev_dir()).unwrap();
    assert_eq!(
        (d.ooc.len(), d.inj.len(), d.idn.len(), d.stale.len()),
        (30, 24, 20, 10)
    );
}

#[test]
fn q2_a_changed_dev3_file_is_refused() {
    let dst = tmp("dev3copy");
    for f in [
        "dev3_out_of_corpus.jsonl",
        "dev3_injection.jsonl",
        "dev3_id_named.jsonl",
        "dev3_stale.jsonl",
        "DEV3_FROZEN.json",
    ] {
        std::fs::copy(dev_dir().join(f), dst.join(f)).unwrap();
    }
    let mut t = std::fs::read_to_string(dst.join("dev3_stale.jsonl")).unwrap();
    t.push('\n');
    std::fs::write(dst.join("dev3_stale.jsonl"), t).unwrap();
    assert!(r3eval::load_dev3(&dst).is_err());
}

#[test]
fn q3_the_dev3_report_has_every_block_with_bounds() {
    let d = r3eval::load_dev3(&dev_dir()).unwrap();
    let (off, on) = r2eval::configs();
    let rep = r3eval::run_dev3(&real(), "v", &d, &[], &off, &on);
    for k in [
        "out_of_corpus_name_list_off",
        "out_of_corpus_name_list_on",
        "injection",
        "id_named_regression",
        "stale_regression",
    ] {
        assert!(rep.get(k).is_some(), "{k}");
    }
    assert_eq!(rep["out_of_corpus_name_list_off"]["n"], 30);
    assert!(rep["injection"]["by_family"].as_object().unwrap().len() >= 12);
    assert!(serde_json::to_string(&rep).unwrap().contains("upper95"));
}

#[test]
fn q4_the_r3_heldout_runner_is_pinned_to_the_orders_sha_and_judges_the_bars() {
    assert_eq!(
        r3eval::HELDOUT_R3_SHA256,
        "e229bb58d40d655a719f3fdeacfb9934069dd91012eedd14072edbcbc2d90962"
    );
    let body = json!({"description_only":[{"q":"zebra-secret restore backups monthly","expected":"STD-A:A-2"}],
      "id_named":[{"q":"What does A-1 of STD-A require?","expected":"STD-A:A-1"}],
      "out_of_corpus":[{"q":"zebra-oc what is the airspeed of a swallow","expected":"abstain"}],
      "injection":[],"stale_version":[]});
    let p = tmp("held").join("h.json");
    let bytes = serde_json::to_vec(&body).unwrap();
    std::fs::write(&p, &bytes).unwrap();
    let sha = hex::encode(Sha256::digest(&bytes));
    // a wrong hash is refused by the pinned entry point without echoing content
    let e = r3eval::load_heldout_r3(&p).unwrap_err();
    assert!(!e.contains("zebra"), "{e}");
    let h = r2eval::load_heldout(&p, &sha).unwrap();
    let (off, on) = r2eval::configs();
    let rep = r3eval::run_heldout_r3_with(&real(), "v", &h, &off, &on);
    let s = serde_json::to_string(&rep).unwrap();
    assert!(!s.contains("zebra") && !s.contains("airspeed"));
    assert!(rep["bars"].get("abstention_name_list_off").is_some());
    assert!(rep["bars"].get("injection_obeyed_zero").is_some());
    let _ = Config::default();
}
