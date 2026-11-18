//! The decision review council ledger on the node: a third ledger beside the AI-decision and evidence ledgers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("co-{name}-{}-{nanos}", std::process::id()))
}

fn run(args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_entropa-platinum"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

const OPEN: &str = r#"{"label":"council_session","actor":"scheduler-agent","decision":"info","reason":"none","subject":"weekly session 45 opened","session_id":"council-2026-w45"}"#;
const FINDING: &str = r#"{"label":"council_finding","actor":"critic-agent","decision":"info","reason":"none","subject":"two denials had no reason code","session_id":"council-2026-w45","provider":"vertex","model_id":"gemini-flash","input_tokens":900,"output_tokens":120,"cost_micro_usd":400}"#;
const DECIDE: &str = r#"{"label":"council_decision","actor":"human-principal","decision":"allow","reason":"council_accepted","subject":"accept finding 1","session_id":"council-2026-w45"}"#;

#[test]
fn co1_log_and_verify_a_separate_council_ledger() {
    let d = dir("co1");
    assert!(run(&["init", d.to_str().unwrap()], None).status.success());
    for r in [OPEN, FINDING, DECIDE] {
        let o = run(&["log-council", d.to_str().unwrap()], Some(r));
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    let v = run(&["verify-council", d.to_str().unwrap()], None);
    assert!(out(&v).contains("records=3"), "{}", out(&v));
    // the AI-decision ledger is untouched
    let ai = run(&["verify", d.to_str().unwrap()], None);
    assert!(!out(&ai).contains("records=3"));
}

#[test]
fn co2_unknown_fields_and_non_council_labels_are_refused() {
    let d = dir("co2");
    run(&["init", d.to_str().unwrap()], None);
    let extra = OPEN.replace("}", ",\"secret\":\"x\"}");
    assert!(!run(&["log-council", d.to_str().unwrap()], Some(&extra))
        .status
        .success());
    let bad = OPEN.replace("council_session", "nl_query");
    assert!(!run(&["log-council", d.to_str().unwrap()], Some(&bad))
        .status
        .success());
    let ssn = OPEN.replace(
        "weekly session 45 opened",
        &format!("patient {}-{}-{}", 123, 45, 6789),
    );
    assert!(!run(&["log-council", d.to_str().unwrap()], Some(&ssn))
        .status
        .success());
}

#[test]
fn co3_the_export_has_plain_english_and_never_the_raw_text() {
    let d = dir("co3");
    run(&["init", d.to_str().unwrap()], None);
    for r in [OPEN, FINDING, DECIDE] {
        run(&["log-council", d.to_str().unwrap()], Some(r));
    }
    let o = run(&["export-council", d.to_str().unwrap()], None);
    let text = out(&o);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(!text.contains("two denials"), "raw text leaked");
    assert!(!text.contains("accept finding"), "raw text leaked");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["records"].as_array().unwrap().len(), 3);
    let plain: Vec<String> = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["plain"].as_str().unwrap().to_string())
        .collect();
    assert!(
        plain.iter().any(|p| p.contains("critic filed a finding")),
        "{plain:?}"
    );
    assert!(
        plain.iter().any(|p| p.contains("accepted a finding")),
        "{plain:?}"
    );
}

#[test]
fn co4_a_closed_output_pipe_is_quiet_not_a_panic() {
    let d = dir("co4");
    run(&["init", d.to_str().unwrap()], None);
    run(&["log-council", d.to_str().unwrap()], Some(OPEN));
    // many exports, each with stdout closed before the program writes
    for _ in 0..5 {
        let mut child = Command::new(env!("CARGO_BIN_EXE_entropa-platinum"))
            .args(["export-council", d.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let o = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(!err.contains("panicked"), "{err}");
    }
}
