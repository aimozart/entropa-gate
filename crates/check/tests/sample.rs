//! The shipped sample: against the FLAWED guard the run shows a FAIL (the planted miss) and a forecast miss; against the FIXED guard a PASS and a forecast hit. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_check::sealed::{run, Options};
use std::path::PathBuf;

fn sample(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("sample")
        .join(file)
}
fn opts(dir: &std::path::Path, guard: &str, out: &str) -> Options {
    let set = sample("sample-set.json");
    Options {
        sha: sha(&std::fs::read(&set).unwrap()),
        file: set,
        out: dir.join(out),
        target: sample(guard),
        args: vec![],
        forecast: Some(sample("sample-forecast.json")),
        prereg: None,
        no_prereg: true,
        runner: None,
        anchor_ledger: None,
    }
}

#[test]
fn m1_the_flawed_sample_guard_fails_honestly_and_the_forecast_is_missed() {
    let d = scratch("m1");
    let v: serde_json::Value =
        serde_json::from_str(&run(&opts(&d, "guard-flawed.sh", "r.json")).unwrap()).unwrap();
    assert_eq!(v["totals"]["cases"], 40);
    assert_eq!(
        v["totals"]["failed"], 8,
        "the 8 lower-case keys slip through"
    );
    assert_eq!(v["totals"]["accepted_attacks"], 8);
    assert_eq!(v["classes"]["clean"]["failed"], 0);
    assert_eq!(v["classes"]["keys"]["failed"], 8);
    let ids: Vec<&str> = v["classes"]["keys"]["failed_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    assert!(
        ids.iter().all(|i| i.starts_with("key-low-")) && ids.len() == 8,
        "{ids:?}"
    );
    let rows = v["calibration"].as_array().unwrap();
    assert!(
        rows.iter().all(|r| r["result"] == "miss"),
        "the forecast of a clean guard is missed: {rows:?}"
    );
    assert_eq!(
        rows.iter().find(|r| r["metric"] == "failed_rate").unwrap()["bar"],
        "missed"
    );
}

#[test]
fn m2_the_fixed_sample_guard_passes_and_the_forecast_is_a_hit() {
    let d = scratch("m2");
    let v: serde_json::Value =
        serde_json::from_str(&run(&opts(&d, "guard-fixed.sh", "r.json")).unwrap()).unwrap();
    assert_eq!(v["totals"]["failed"], 0);
    assert_eq!(v["totals"]["accepted_attacks"], 0);
    let rows = v["calibration"].as_array().unwrap();
    assert!(rows.iter().all(|r| r["result"] == "hit"), "{rows:?}");
    assert_eq!(
        rows.iter().find(|r| r["metric"] == "failed_rate").unwrap()["bar"],
        "met"
    );
    // with zero failures the upper bound is the rule of three: 1 - 0.05^(1/40)
    assert!(
        (v["totals"]["upper95_of_failure_rate"].as_f64().unwrap() - 0.07216).abs() < 1e-4,
        "{}",
        v["totals"]
    );
}

#[test]
fn m3_the_sample_has_no_real_secret_shapes() {
    let text = std::fs::read_to_string(sample("sample-set.json")).unwrap();
    for bad in ["AKIA", "BEGIN PRIVATE", "ghp_", "sk-", "xoxb-"] {
        assert!(!text.contains(bad), "{bad}");
    }
    assert!(text.contains("SYNKEY-") && text.to_lowercase().contains("synkey-"));
}
