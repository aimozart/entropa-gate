//! Stage E-LABELS-3 at the command line: log-evidence accepts corpus_version on evidence.change and retrieval_record on evidence.access, refuses
//! them on every other kind, and the evidence ledger still verifies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cv-{name}-{}-{nanos}", std::process::id()))
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

fn ev(kind: &str, label: &str, control: &str) -> String {
    format!(
        r#"{{"kind":"{kind}","label":"{label}","decision":"allow","reason":"check_passed","control":"{control}","total":3,"passed":3,"flagged":0,"detail":"corpus_hash=aaaa|passages=x","run_id":"r1-demo"}}"#
    )
}

#[test]
fn cv1_log_evidence_accepts_each_label_on_its_own_kind_and_the_ledger_verifies() {
    let d = dir("cv1");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for (k, l, c) in [
        ("evidence.change", "corpus_version", "nist_800_53_au_9"),
        ("evidence.access", "retrieval_record", "eu_ai_act_art_12"),
        ("evidence.access", "retrieval_record", "pci_dss_12_3_3"),
        ("evidence.change", "corpus_version", "dora_rts_art_12"),
    ] {
        let o = run(&["log-evidence", ds], Some(&ev(k, l, c)));
        assert!(
            o.status.success(),
            "{l}/{c}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=4 checkpoints=4"));
}

#[test]
fn cv2_each_label_is_refused_on_every_other_kind_and_nothing_is_written() {
    let d = dir("cv2");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for (l, wrong) in [
        (
            "corpus_version",
            [
                "evidence.access",
                "evidence.control_check",
                "evidence.policy",
                "evidence.pipeline_run",
            ],
        ),
        (
            "retrieval_record",
            [
                "evidence.change",
                "evidence.control_check",
                "evidence.policy",
                "evidence.pipeline_run",
            ],
        ),
    ] {
        for k in wrong {
            assert!(
                !run(&["log-evidence", ds], Some(&ev(k, l, "nist_800_53_au_9")))
                    .status
                    .success(),
                "{l} on {k}"
            );
        }
    }
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=0"));
}

#[test]
fn cv3_no_new_control_code_exists_and_unknown_codes_are_still_refused() {
    let d = dir("cv3");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for c in [
        "corpus_hash",
        "retrieval",
        "nist_800_53_au_11",
        "soc2_cc7_2",
    ] {
        assert!(
            !run(
                &["log-evidence", ds],
                Some(&ev("evidence.access", "retrieval_record", c))
            )
            .status
            .success(),
            "{c}"
        );
    }
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=0"));
}

#[test]
fn cv4_the_old_labels_still_work_on_their_kinds() {
    let d = dir("cv4");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    assert!(run(
        &["log-evidence", ds],
        Some(&ev("evidence.access", "table_read", "hipaa_164_312_b"))
    )
    .status
    .success());
    assert!(run(
        &["log-evidence", ds],
        Some(&ev("evidence.change", "deploy", "hitrust_10_sdlc"))
    )
    .status
    .success());
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=2"));
}
