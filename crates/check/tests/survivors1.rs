//! Tests added after the first mutation rounds (a stage record (not published)): bar operators at their boundaries, the forecast limits, exact prereg fields, per-class accepted attacks, and the printed summary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_check::forecast;
use entropa_check::prereg::{make, verify, Hashes};
use entropa_check::sealed::{run, Options};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn set_json() -> String {
    // 4 cases: one failure (c3: allowed although block was expected, an attack) -> failed_rate 0.25
    r#"{"schema":"entropa-sealed-v1","cases":[
 {"id":"c1","class":"plain","input":{"text":"hello"},"expect":"allow"},
 {"id":"c2","class":"plain","input":{"text":"BAD"},"expect":"block","attack":true},
 {"id":"c3","class":"attacks","input":{"text":"sneaky"},"expect":"block","attack":true},
 {"id":"c4","class":"attacks","input":{"text":"sneaky two"},"expect":"block","attack":true}]}"#
        .to_string()
}

#[test]
fn y1_every_bar_operator_is_judged_at_its_boundary() {
    let dir = scratch("y1");
    let text = set_json();
    let set = write(&dir, "set.json", &text);
    let target = script(&dir, "guard", GUARD);
    // measured: failed_rate 0.25 (c3 and c4 are allowed attacks: 2 of 4 fail => 0.5); compute from the set: c1 ok, c2 ok (BAD blocked), c3 fail, c4 fail
    let cases = [
        ("<", 0.5, "missed"),
        ("<", 0.6, "met"),
        ("<=", 0.5, "met"),
        ("<=", 0.4, "missed"),
        (">=", 0.5, "met"),
        (">=", 0.6, "missed"),
        (">", 0.5, "missed"),
        (">", 0.4, "met"),
    ];
    let metrics: Vec<String> = cases.iter().map(|(op, v, _)| format!(r#"{{"name":"failed_rate","low":0.0,"central":0.5,"high":1.0,"bar":{{"op":"{op}","value":{v}}}}}"#)).collect();
    let fc = write(
        &dir,
        "fc.json",
        &format!(
            r#"{{"schema":"entropa-forecast-v1","stage":"Y","written":"2026-11-18","metrics":[{}]}}"#,
            metrics.join(",")
        ),
    );
    let o = Options {
        file: set,
        sha: sha(text.as_bytes()),
        out: dir.join("r.json"),
        target,
        args: vec![],
        forecast: Some(fc),
        prereg: None,
        no_prereg: true,
        runner: None,
        anchor_ledger: None,
    };
    let v: serde_json::Value = serde_json::from_str(&run(&o).unwrap()).unwrap();
    let rows = v["calibration"].as_array().unwrap();
    assert_eq!(rows.len(), cases.len());
    for (row, (op, val, want)) in rows.iter().zip(cases) {
        assert_eq!(row["measured"].as_f64(), Some(0.5));
        assert_eq!(row["bar"], want, "measured 0.5 {op} {val}");
    }
    // the per-class accepted-attack counts are exact (c3 and c4 were allowed)
    assert_eq!(v["classes"]["attacks"]["accepted_attacks"], 2);
    assert_eq!(v["classes"]["plain"]["accepted_attacks"], 0);
    assert_eq!(v["totals"]["accepted_attacks"], 2);
}

fn fc(extra_low: &str, written: &str) -> String {
    format!(
        r#"{{"schema":"entropa-forecast-v1","stage":"Y","written":"{written}","metrics":[{{"name":"failed_rate","low":{extra_low},"central":0.1,"high":0.2}}]}}"#
    )
}

#[test]
fn y2_forecast_limits() {
    assert!(forecast::parse(fc("0.0", "2026-11-18").as_bytes()).is_ok());
    assert!(
        forecast::parse(fc("-0.1", "2026-11-18").as_bytes()).is_err(),
        "negative numbers are refused"
    );
    assert!(
        forecast::parse(fc("0.0", "").as_bytes()).is_err(),
        "written must not be empty"
    );
    assert!(
        forecast::parse(fc("0.0", &"x".repeat(40)).as_bytes()).is_ok(),
        "40 characters are accepted"
    );
    assert!(
        forecast::parse(fc("0.0", &"x".repeat(41)).as_bytes()).is_err(),
        "41 are refused"
    );
    // exactly 1 MiB is accepted, one byte more is refused
    let base = fc("0.0", "2026-11-18");
    let pad = |n: usize| format!("{base}{}", " ".repeat(n - base.len()));
    assert!(forecast::parse(pad(1024 * 1024).as_bytes()).is_ok());
    assert!(forecast::parse(pad(1024 * 1024 + 1).as_bytes()).is_err());
}

#[test]
fn y3_a_prereg_record_must_have_exactly_the_fields_of_the_schema() {
    let d = scratch("y3");
    let f = write(&d, "k", &format!("{}\n", "7a".repeat(32)));
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pk = entropa_core::Probe::from_signing_key_hex(&"7a".repeat(32))
        .unwrap()
        .pubkey_hex();
    let h = Hashes {
        set: "11".repeat(32),
        forecast: "22".repeat(32),
        runner: "33".repeat(32),
        target: "44".repeat(32),
    };
    let rec = make("S1", &h, &f, &[]).unwrap();
    assert!(verify(&rec, &pk).is_ok());
    let mut v: serde_json::Value = serde_json::from_str(&rec).unwrap();
    v["extra"] = serde_json::json!("x");
    let e = verify(&v.to_string(), &pk).unwrap_err();
    assert!(
        e.0.contains("exactly the fields"),
        "an extra field (outside the signature) is refused: {e}"
    );
    let mut v: serde_json::Value = serde_json::from_str(&rec).unwrap();
    v.as_object_mut().unwrap().remove("target_sha256");
    assert!(verify(&v.to_string(), &pk)
        .unwrap_err()
        .0
        .contains("exactly the fields"));
    // renaming one field keeps the count but not the names
    let mut v: serde_json::Value = serde_json::from_str(&rec).unwrap();
    let t = v.as_object_mut().unwrap().remove("target_sha256").unwrap();
    v["other_sha256"] = t;
    assert!(verify(&v.to_string(), &pk)
        .unwrap_err()
        .0
        .contains("exactly the fields"));
}

#[test]
fn y4_the_printed_summary_counts_hits_and_misses_exactly() {
    let sample = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("sample");
    let d = scratch("y4");
    let set = sample.join("sample-set.json");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_entropa-check"))
        .args([
            "sealed",
            "--file",
            set.to_str().unwrap(),
            "--sha",
            &sha(&std::fs::read(&set).unwrap()),
            "--out",
            d.join("r.json").to_str().unwrap(),
            "--target",
            sample.join("guard-flawed.sh").to_str().unwrap(),
            "--forecast",
            sample.join("sample-forecast.json").to_str().unwrap(),
            "--no-prereg",
        ])
        .output()
        .unwrap();
    let t = String::from_utf8_lossy(&o.stdout);
    assert!(t.contains("forecast: 0 hit, 3 miss"), "{t}");
    let d2 = scratch("y4b");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_entropa-check"))
        .args([
            "sealed",
            "--file",
            set.to_str().unwrap(),
            "--sha",
            &sha(&std::fs::read(&set).unwrap()),
            "--out",
            d2.join("r.json").to_str().unwrap(),
            "--target",
            sample.join("guard-fixed.sh").to_str().unwrap(),
            "--forecast",
            sample.join("sample-forecast.json").to_str().unwrap(),
            "--no-prereg",
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("forecast: 3 hit, 0 miss"));
}
