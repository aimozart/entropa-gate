//! EG1 task 3: the sealed-set runner (`heldout-eg`): the hash is checked before anything is parsed, a second run is refused, the schema of
//! `eg-sealed-v1` is read as written, and the report holds counts, bounds and ids only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_egress-eval"))
        .args(args)
        .output()
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn case(
    id: &str,
    class: &str,
    sub: &str,
    tier: &str,
    body: Value,
    expect: &str,
    canaries: &[&str],
) -> Value {
    json!({"id": id, "class": class, "subclass": sub, "tier": tier,
        "request": {"destination": "https://api.model.example/v1/chat", "headers": {}, "body_fields": body, "attachments": []},
        "expect": expect, "canaries": canaries})
}
fn set() -> Value {
    let mut cases = vec![
        case(
            "s-1",
            "secrets",
            "plain",
            "T1",
            json!({"msg": "key AKIAIOSFODNN7EXAMPLE here"}),
            "no_leak",
            &["AKIAIOSFODNN7EXAMPLE"],
        ),
        case(
            "s-2",
            "secrets",
            "plain",
            "T1",
            json!({"msg": "a harmless note"}),
            "no_leak",
            &["AKIAIOSFODNN7EXAMPLE"],
        ),
        case(
            "c-1",
            "clean",
            "prose",
            "T1",
            json!({"msg": "Please summarise the audit log retention clause."}),
            "allow",
            &[],
        ),
        case(
            "c-2",
            "clean",
            "prose",
            "T1",
            json!({"msg": "paid with 4111111111111111 today"}),
            "allow",
            &[],
        ),
        case(
            "d-1",
            "dest",
            "scheme",
            "T1",
            json!({"msg": "hi"}),
            "block",
            &[],
        ),
        case("t-1", "t0", "all", "T0", json!({"msg": "hi"}), "block", &[]),
        case(
            "e-1",
            "compat",
            "ligature",
            "T1",
            json!({"msg": "hello"}),
            "either",
            &[],
        ),
        case(
            "r-1",
            "compat",
            "ligature",
            "T1",
            json!({"msg": "x"}),
            "no_leak_report_only",
            &["zzz-canary"],
        ),
        case(
            "p-1",
            "pii",
            "email_allowed_by_policy",
            "T1",
            json!({"msg": "mail leak.person@example.com"}),
            "no_leak",
            &["leak.person@example.com"],
        ),
    ];
    cases[4]["request"]["destination"] = json!("http://api.model.example/v1/chat");
    json!({"schema": "eg-sealed-v1",
        "policy": {"destinations": [{"tier": "T1", "url_prefix": "https://api.model.example/v1/"}, {"tier": "T2", "url_prefix": "https://api.model.example/v1/"}],
                   "do_not_send_terms": [], "modes": {"D5.email": "allow_with_record", "D9": "block"}},
        "cases": cases})
}

#[test]
fn h1_the_hash_is_checked_before_parsing_and_a_second_run_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("set.json");
    std::fs::write(&f, b"this is not json at all").unwrap();
    let out = d.path().join("rep.json");
    let (code, err) = run(&[
        "heldout-eg",
        "--file",
        f.to_str().unwrap(),
        "--sha",
        &"0".repeat(64),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("nothing was parsed"), "{err}");
    assert!(!out.exists());
    // right hash, but not JSON: an error (1), not a refusal, and no report
    let (code, _) = run(&[
        "heldout-eg",
        "--file",
        f.to_str().unwrap(),
        "--sha",
        &sha(b"this is not json at all"),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 1);
    assert!(!out.exists());
}

#[test]
fn h2_the_schema_is_read_as_written_and_the_report_has_counts_bounds_and_ids_only() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("set.json");
    let bytes = serde_json::to_vec(&set()).unwrap();
    std::fs::write(&f, &bytes).unwrap();
    let out = d.path().join("rep.json");
    let (code, err) = run(&[
        "heldout-eg",
        "--file",
        f.to_str().unwrap(),
        "--sha",
        &sha(&bytes),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    let text = std::fs::read_to_string(&out).unwrap();
    for secret in [
        "AKIAIOSFODNN7EXAMPLE",
        "leak.person@example.com",
        "zzz-canary",
        "audit log",
    ] {
        assert!(!text.contains(secret), "{secret} in the report");
    }
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["schema"], "eg-sealed-report-v1");
    assert_eq!(r["set_sha256"], sha(&bytes));
    assert_eq!(
        r["ignored_unknown_detector_modes"], 1,
        "D9 is not a detector"
    );
    let c = &r["classes"];
    assert_eq!(c["secrets"]["evaluated"], 2);
    assert_eq!(
        c["secrets"]["failed"], 0,
        "a blocked secret and a clean request are not leaks: {r}"
    );
    assert_eq!(c["clean"]["evaluated"], 2);
    assert_eq!(
        c["clean"]["failed"], 1,
        "a blocked request counts as a false positive for expect=allow"
    );
    assert_eq!(c["clean"]["failed_ids"], json!(["c-2"]));
    // EG1b: every class reports how often each reason occurred and which cases ended in `internal_error` (a caught panic is a block that
    // must not hide inside the false-positive count)
    let reasons = c["clean"]["reasons"]
        .as_object()
        .expect("reasons per class");
    assert_eq!(
        reasons.values().map(|v| v.as_u64().unwrap()).sum::<u64>(),
        2,
        "one reason per case: {r}"
    );
    assert_eq!(c["clean"]["internal_error_ids"], json!([]));
    assert_eq!(c["secrets"]["internal_error_ids"], json!([]));
    assert_eq!(c["dest"]["failed"], 0);
    assert_eq!(c["t0"]["failed"], 0);
    assert_eq!(
        c["compat"]["evaluated"], 0,
        "either and report-only are not bars"
    );
    assert_eq!(c["compat"]["either_counts"]["allow"], 1);
    assert_eq!(c["compat"]["report_only"]["cases"], 1);
    assert_eq!(c["compat"]["report_only"]["leaks"], 0);
    // a policy that allows email with a record: the canary is sent byte for byte, which is a leak
    assert_eq!(c["pii"]["failed"], 1, "{r}");
    assert!(
        c["secrets"]["upper95_of_failure_rate"].as_f64().unwrap() > 0.2,
        "n=2, zero failures"
    );
    // a second run is refused and the first report is untouched
    let (code, _) = run(&[
        "heldout-eg",
        "--file",
        f.to_str().unwrap(),
        "--sha",
        &sha(&bytes),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 3);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), text);
}

#[test]
fn h3_an_invalid_policy_in_the_file_is_refused_not_run() {
    let d = tempfile::tempdir().unwrap();
    let mut s = set();
    s["policy"]["modes"] = json!({"D1": "redact"}); // D1 may not be below block at T3
    let bytes = serde_json::to_vec(&s).unwrap();
    let f = d.path().join("set.json");
    std::fs::write(&f, &bytes).unwrap();
    let out = d.path().join("rep.json");
    let (code, err) = run(&[
        "heldout-eg",
        "--file",
        f.to_str().unwrap(),
        "--sha",
        &sha(&bytes),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("policy refused"), "{err}");
    assert!(!Path::new(&out).exists());
}

#[test]
fn l1_the_latency_command_reports_ordered_percentiles_per_size() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("lat.json");
    let (code, err) = run(&["latency", "--n", "20", "--out", out.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    let r: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(r["runs_per_size"], 20);
    let sizes = r["sizes"].as_array().expect("sizes");
    assert_eq!(
        sizes
            .iter()
            .map(|s| s["bytes"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1024, 16384, 65536]
    );
    for s in sizes {
        let (p50, p95, mx) = (
            s["p50_ms"].as_f64().unwrap(),
            s["p95_ms"].as_f64().unwrap(),
            s["max_ms"].as_f64().unwrap(),
        );
        assert!(0.0 <= p50 && p50 <= p95 && p95 <= mx, "{s}");
        assert_eq!(s["internal_errors"], 0);
    }
    // no request text in the report
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(!text.contains("AKIA"), "{text}");
}
