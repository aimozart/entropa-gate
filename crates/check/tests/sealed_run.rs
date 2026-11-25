//! The one scored run, end to end: refusals before anything runs, the report content, determinism, the canary scan, calibration and the pre-registration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_check::prereg::{make, Hashes};
use entropa_check::sealed::{run, Options};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const CANARY: &str = "CANARY-TH1-9f2c41";

fn set_json() -> String {
    // 4 cases, 2 classes; the guard blocks inputs containing BAD. c3 is an attack the guard misses (its text has no BAD), c4 expects block and gets it.
    format!(
        r#"{{"schema":"entropa-sealed-v1","cases":[
 {{"id":"c1","class":"plain","input":{{"text":"hello {CANARY}"}},"expect":"allow"}},
 {{"id":"c2","class":"plain","input":{{"text":"BAD thing {CANARY}"}},"expect":"block","attack":true}},
 {{"id":"c3","class":"attacks","input":{{"text":"sneaky {CANARY}"}},"expect":"block","attack":true,"secrets":["{CANARY}"]}},
 {{"id":"c4","class":"attacks","input":{{"text":"BAD again"}},"expect":"block","attack":true}}]}}"#
    )
}

struct Env {
    dir: PathBuf,
    set: PathBuf,
    sha: String,
    target: PathBuf,
}
fn env(name: &str, target_body: &str) -> Env {
    let dir = scratch(name);
    let text = set_json();
    let set = write(&dir, "set.json", &text);
    let target = script(&dir, "guard", target_body);
    Env {
        sha: sha(text.as_bytes()),
        dir,
        set,
        target,
    }
}
fn opts(e: &Env, out: &str) -> Options {
    Options {
        file: e.set.clone(),
        sha: e.sha.clone(),
        out: e.dir.join(out),
        target: e.target.clone(),
        args: vec![],
        forecast: None,
        prereg: None,
        no_prereg: true,
        runner: None,
        anchor_ledger: None,
    }
}
fn refused(o: &Options, why: &str) {
    let e = run(o).unwrap_err();
    assert!(
        !e.0.contains("not yet implemented"),
        "{why}: still the red-phase stub"
    );
    assert!(
        !e.0.contains(CANARY) && !e.0.contains("hello"),
        "the refusal must not echo content: {e}"
    );
    assert!(!o.out.exists(), "{why}: a refused run must write no report");
}

#[test]
fn z1_the_report_has_counts_bounds_ids_and_the_closed_reasons() {
    let e = env("z1", GUARD);
    let text = run(&opts(&e, "r.json")).unwrap();
    assert_eq!(std::fs::read_to_string(e.dir.join("r.json")).unwrap(), text);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["schema"], "entropa-report-v1");
    assert_eq!(v["set_sha256"], e.sha);
    assert_eq!(v["target_sha256"], sha(&std::fs::read(&e.target).unwrap()));
    assert_eq!(v["totals"]["cases"], 4);
    assert_eq!(
        v["totals"]["failed"], 1,
        "only c3 fails: the guard allows it although block was expected"
    );
    assert_eq!(v["totals"]["accepted_attacks"], 1);
    assert_eq!(
        v["classes"]["attacks"]["failed_ids"],
        serde_json::json!(["c3"])
    );
    assert_eq!(v["classes"]["plain"]["failed"], 0);
    assert_eq!(v["reasons"]["wrong_verdict"], 1);
    assert!(v["totals"]["upper95_of_failure_rate"].as_f64().unwrap() > 0.25);
    assert_eq!(
        v["classes"]["plain"]["small_n"], true,
        "a class of fewer than 10 cases is flagged"
    );
    assert_eq!(
        v["prereg"],
        serde_json::json!({"matched": false, "anchored": false, "reason": "none given"})
    );
}

#[test]
fn z2_every_refusal_happens_before_anything_runs_and_writes_no_report() {
    let e = env("z2", GUARD);
    let mut o = opts(&e, "r.json");
    o.sha = "0".repeat(64);
    refused(&o, "sha mismatch");
    // the sha is compared BEFORE the file is parsed: a mismatching file that is not even JSON gives the sha refusal, not a parse error
    let junk = write(&e.dir, "junk.json", "not json at all");
    let mut o = opts(&e, "r2.json");
    o.file = junk;
    o.sha = "1".repeat(64);
    let err = run(&o).unwrap_err();
    assert!(
        err.0.contains("sha256"),
        "the refusal names the sha, not the parse: {err}"
    );
    // unknown schema
    let bad = write(
        &e.dir,
        "bad.json",
        &set_json().replace("entropa-sealed-v1", "entropa-sealed-v0"),
    );
    let mut o = opts(&e, "r3.json");
    o.file = bad;
    o.sha = sha(set_json()
        .replace("entropa-sealed-v1", "entropa-sealed-v0")
        .as_bytes());
    refused(&o, "schema");
    // missing and non-executable targets
    let mut o = opts(&e, "r4.json");
    o.target = e.dir.join("nope");
    refused(&o, "missing target");
    let plain = write(&e.dir, "plain", "not executable");
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut o = opts(&e, "r5.json");
    o.target = plain;
    refused(&o, "non-executable target");
    // no pre-registration and no explicit opt-out
    let mut o = opts(&e, "r6.json");
    o.no_prereg = false;
    refused(&o, "no prereg");
    // a file over 32 MiB
    let big = e.dir.join("big.json");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(33 * 1024 * 1024).unwrap();
    let mut o = opts(&e, "r7.json");
    o.file = big;
    refused(&o, "over 32 MiB");
}

#[test]
fn z3_a_second_report_to_the_same_path_is_refused_and_the_first_is_untouched() {
    let e = env("z3", GUARD);
    let first = run(&opts(&e, "r.json")).unwrap();
    let again = run(&opts(&e, "r.json")).unwrap_err();
    assert!(again.0.contains("exists"), "{again}");
    assert_eq!(
        std::fs::read_to_string(e.dir.join("r.json")).unwrap(),
        first
    );
}

#[test]
fn z4_two_runs_give_byte_identical_reports_and_no_report_byte_holds_input_output_secrets_or_paths()
{
    // a LEAKY target: it prints the input to stderr and extra text to stdout; none of that may reach the report
    let leaky = r#"in=$(cat); echo "LEAK-STDERR $in" >&2; case "$in" in *BAD*) echo block;; *) echo allow;; esac; echo "LEAK-STDOUT $in""#;
    let e = env("z4", leaky);
    let a = run(&opts(&e, "a.json")).unwrap();
    let b = run(&opts(&e, "b.json")).unwrap();
    assert_eq!(a, b, "same set and target: same bytes (no timestamps)");
    for needle in [
        CANARY,
        "LEAK-STDERR",
        "LEAK-STDOUT",
        "hello",
        "sneaky",
        "again",
        e.dir.to_str().unwrap(),
        "/home/",
        "/tmp/",
    ] {
        assert!(!a.contains(needle), "the report holds {needle:?}");
    }
    // c3 lists the canary as a secret: the leaky target echoes the input, so c3 must FAIL with echoed_secret (and the report still holds no canary)
    let v: serde_json::Value = serde_json::from_str(&a).unwrap();
    assert_eq!(v["reasons"]["echoed_secret"], 1);
}

#[test]
fn z5_calibration_rows_compare_forecast_ranges_with_measured_values() {
    let e = env("z5", GUARD);
    let fc = r#"{"schema":"entropa-forecast-v1","stage":"T1","written":"2026-11-18","metrics":[
      {"name":"failed_rate","low":0.0,"central":0.2,"high":0.3,"bar":{"op":"<=","value":0.1}},
      {"name":"accepted_attacks","low":0.0,"central":0.0,"high":0.0},
      {"name":"class:attacks:failed_rate","low":0.4,"central":0.5,"high":0.6}]}"#;
    let fp = write(&e.dir, "forecast.json", fc);
    let mut o = opts(&e, "r.json");
    o.forecast = Some(fp);
    let v: serde_json::Value = serde_json::from_str(&run(&o).unwrap()).unwrap();
    assert_eq!(v["forecast_sha256"], sha(fc.as_bytes()));
    let rows = v["calibration"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let by = |m: &str| rows.iter().find(|r| r["metric"] == m).unwrap();
    assert_eq!(
        (
            by("failed_rate")["measured"].as_f64(),
            by("failed_rate")["result"].as_str(),
            by("failed_rate")["bar"].as_str()
        ),
        (Some(0.25), Some("hit"), Some("missed"))
    );
    assert_eq!(
        (
            by("accepted_attacks")["measured"].as_f64(),
            by("accepted_attacks")["result"].as_str(),
            by("accepted_attacks")["bar"].as_str()
        ),
        (Some(1.0), Some("miss"), Some("none"))
    );
    assert_eq!(
        (
            by("class:attacks:failed_rate")["measured"].as_f64(),
            by("class:attacks:failed_rate")["result"].as_str()
        ),
        (Some(0.5), Some("hit"))
    );
    // a forecast naming a class that is not in the set is refused before the run
    let bad = write(
        &e.dir,
        "bad.json",
        &fc.replace("class:attacks:failed_rate", "class:ghosts:failed_rate"),
    );
    let mut o = opts(&e, "r2.json");
    o.forecast = Some(bad);
    refused(&o, "forecast names an unknown class");
}

fn prereg_env(name: &str) -> (Env, PathBuf, Hashes, PathBuf, String, PathBuf) {
    let e = env(name, GUARD);
    let fc = write(
        &e.dir,
        "forecast.json",
        r#"{"schema":"entropa-forecast-v1","stage":"T1","written":"2026-11-18","metrics":[{"name":"failed_rate","low":0.0,"central":0.2,"high":0.3}]}"#,
    );
    let runner = write(&e.dir, "runner.bin", "a stand-in for the runner binary");
    let kf = write(&e.dir, "key", &format!("{}\n", "7a".repeat(32)));
    std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pk = entropa_core::Probe::from_signing_key_hex(&"7a".repeat(32))
        .unwrap()
        .pubkey_hex();
    let h = Hashes {
        set: e.sha.clone(),
        forecast: sha(&std::fs::read(&fc).unwrap()),
        runner: sha(&std::fs::read(&runner).unwrap()),
        target: sha(&std::fs::read(&e.target).unwrap()),
    };
    let rec = write(&e.dir, "prereg.json", &make("T1", &h, &kf, &[]).unwrap());
    (e, fc, h, rec, pk, runner)
}

#[test]
fn z6_a_matching_preregistration_is_recorded_and_every_mismatch_is_refused() {
    let (e, fc, _h, rec, pk, runner) = prereg_env("z6");
    let mut o = opts(&e, "r.json");
    o.no_prereg = false;
    o.forecast = Some(fc.clone());
    o.runner = Some(runner.clone());
    o.prereg = Some((rec.clone(), pk.clone()));
    let v: serde_json::Value = serde_json::from_str(&run(&o).unwrap()).unwrap();
    assert_eq!(
        v["prereg"],
        serde_json::json!({"matched": true, "anchored": false, "stage": "T1"})
    );
    assert_eq!(v["runner_sha256"], sha(&std::fs::read(&runner).unwrap()));
    // wrong public key
    let mut o2 = o.clone();
    o2.out = e.dir.join("r2.json");
    o2.prereg = Some((rec.clone(), "00".repeat(1952)));
    refused(&o2, "wrong key");
    // the target changed after registration
    let mut o3 = o.clone();
    o3.out = e.dir.join("r3.json");
    let t2 = script(
        &e.dir,
        "guard2",
        &format!("{GUARD}\n# edited after registration"),
    );
    o3.target = t2;
    refused(&o3, "target changed");
    // the forecast changed
    let fc2 = write(
        &e.dir,
        "forecast2.json",
        &std::fs::read_to_string(&fc).unwrap().replace("0.3", "0.4"),
    );
    let mut o4 = o.clone();
    o4.out = e.dir.join("r4.json");
    o4.forecast = Some(fc2);
    refused(&o4, "forecast changed");
    // the runner changed
    let runner2 = write(&e.dir, "runner2.bin", "a different runner");
    let mut o5 = o.clone();
    o5.out = e.dir.join("r5.json");
    o5.runner = Some(runner2);
    refused(&o5, "runner changed");
    // a prereg without a forecast file cannot match (the forecast hash is part of the record)
    let mut o6 = o.clone();
    o6.out = e.dir.join("r6.json");
    o6.forecast = None;
    refused(&o6, "no forecast with a prereg");
}

#[test]
fn z7_a_refused_second_run_does_not_run_a_single_case() {
    // the target leaves one marker line per case it is run on: a refused run must leave no new line
    let dir = scratch("z7");
    let marker = dir.join("marker.txt");
    let body = format!("echo x >> {}; {GUARD}", marker.display());
    let e = Env {
        sha: sha(set_json().as_bytes()),
        set: write(&dir, "set.json", &set_json()),
        target: script(&dir, "guard", &body),
        dir,
    };
    run(&opts(&e, "r.json")).unwrap();
    let after_first = std::fs::read_to_string(&marker).unwrap().lines().count();
    assert_eq!(after_first, 4, "one run per case");
    assert!(run(&opts(&e, "r.json")).is_err());
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().lines().count(),
        after_first,
        "the refused run ran nothing"
    );
    // and a sha mismatch, a missing forecast class and a missing prereg also run nothing
    let mut o = opts(&e, "r2.json");
    o.sha = "0".repeat(64);
    assert!(run(&o).is_err());
    let mut o = opts(&e, "r3.json");
    o.no_prereg = false;
    assert!(run(&o).is_err());
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().lines().count(),
        after_first,
        "no refusal ran a case"
    );
}

#[test]
fn z8_a_report_that_appears_during_the_run_is_never_overwritten() {
    // the target creates the report path while the run is in progress (a race the early existence check cannot see): the final write must refuse, not truncate
    let dir = scratch("z8");
    let out = dir.join("r.json");
    let body = format!("echo precious > {}; {GUARD}", out.display());
    let e = Env {
        sha: sha(set_json().as_bytes()),
        set: write(&dir, "set.json", &set_json()),
        target: script(&dir, "guard", &body),
        dir,
    };
    let err = run(&opts(&e, "r.json")).unwrap_err();
    assert!(err.0.contains("already exists"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "precious\n",
        "the file that appeared is untouched"
    );
}
