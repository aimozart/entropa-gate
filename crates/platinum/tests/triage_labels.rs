//! Stage E-LABELS at the command line: log and log-evidence accept the five triage labels on their kinds and refuse them elsewhere.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tl-{name}-{}-{nanos}", std::process::id()))
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

fn ev(kind: &str, label: &str, decision: &str, reason: &str) -> String {
    format!(
        r#"{{"kind":"{kind}","label":"{label}","decision":"{decision}","reason":"{reason}","control":"policy_p3_separation_of_duties","total":1,"passed":1,"flagged":0,"detail":"case=SYN-CASE-0001|pending=pending-000001","run_id":"approval-SYN-CASE-0001"}}"#
    )
}

fn triage(label: &str) -> String {
    format!(
        r#"{{"label":"{label}","decision":"escalate","reason":"human_required","input":"sha256:aaaa","output":"needs_human|UNDETERMINED|model","run_id":"triage-SYN-CASE-0001","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":0,"output_tokens":0,"cost_micro_usd":0}}"#
    )
}

#[test]
fn tl1_log_accepts_claims_triage_and_refuses_the_other_new_labels() {
    let d = dir("tl1");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    let o = run(&["log", ds], Some(&triage("claims_triage")));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    for l in [
        "policy_verdict",
        "approval_requested",
        "approval_denied",
        "case_outcome",
    ] {
        assert!(!run(&["log", ds], Some(&triage(l))).status.success(), "{l}");
    }
    assert!(out(&run(&["verify", ds], None)).contains("OK records=1"));
}

#[test]
fn tl2_log_evidence_accepts_the_policy_labels_and_case_outcome_on_their_kinds() {
    let d = dir("tl2");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for (kind, label, dec, why) in [
        ("evidence.policy", "policy_verdict", "allow", "guard_passed"),
        (
            "evidence.policy",
            "approval_requested",
            "hold",
            "gate_pending",
        ),
        ("evidence.policy", "approval_denied", "deny", "gate_denied"),
        (
            "evidence.policy",
            "policy_approved",
            "allow",
            "cited_receipts",
        ),
        (
            "evidence.control_check",
            "case_outcome",
            "deny",
            "check_failed",
        ),
    ] {
        let o = run(&["log-evidence", ds], Some(&ev(kind, label, dec, why)));
        assert!(
            o.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=5 checkpoints=5"));
}

#[test]
fn tl3_the_new_labels_are_refused_on_the_wrong_kinds_and_nothing_is_written() {
    let d = dir("tl3");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for (kind, label) in [
        ("evidence.change", "policy_verdict"),
        ("evidence.access", "approval_requested"),
        ("evidence.pipeline_run", "approval_denied"),
        ("evidence.control_check", "approval_denied"),
        ("evidence.policy", "case_outcome"),
        ("evidence.change", "case_outcome"),
        ("evidence.policy", "claims_triage"),
        ("evidence.control_check", "claims_triage"),
    ] {
        let o = run(
            &["log-evidence", ds],
            Some(&ev(kind, label, "allow", "check_passed")),
        );
        assert!(!o.status.success(), "{label} on {kind} must be refused");
    }
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=0"));
}
