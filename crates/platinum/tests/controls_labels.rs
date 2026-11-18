//! Stage E-LABELS-2 at the command line: log-evidence accepts the two new labels with the eight new control codes on evidence.control_check,
//! refuses them on other kinds and refuses unknown control codes, and the ledger still verifies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cl-{name}-{}-{nanos}", std::process::id()))
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
        r#"{{"kind":"{kind}","label":"{label}","decision":"allow","reason":"check_passed","control":"{control}","total":8,"passed":8,"flagged":0,"detail":"hosts=8|cbom=sha256:aaaa","run_id":"e1-crypto-inventory"}}"#
    )
}

const CONTROLS: [&str; 8] = [
    "pci_dss_10_3_4",
    "pci_dss_12_3_3",
    "dora_rts_art_6",
    "dora_rts_art_12",
    "nist_800_53_au_9",
    "nist_800_53_au_10",
    "eu_ai_act_art_12",
    "eu_ai_act_art_19",
];

#[test]
fn cl1_log_evidence_accepts_both_labels_with_every_new_control_and_the_ledger_verifies() {
    let d = dir("cl1");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    let mut n = 0;
    for c in CONTROLS {
        for l in ["crypto_inventory", "log_integrity_check"] {
            let o = run(
                &["log-evidence", ds],
                Some(&ev("evidence.control_check", l, c)),
            );
            assert!(
                o.status.success(),
                "{l}/{c}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            n += 1;
        }
    }
    assert!(out(&run(&["verify-evidence", ds], None))
        .contains(&format!("OK records={n} checkpoints={n}")));
}

#[test]
fn cl2_the_new_labels_are_refused_on_the_wrong_kinds_and_nothing_is_written() {
    let d = dir("cl2");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for kind in [
        "evidence.change",
        "evidence.access",
        "evidence.pipeline_run",
        "evidence.policy",
    ] {
        for l in ["crypto_inventory", "log_integrity_check"] {
            assert!(
                !run(&["log-evidence", ds], Some(&ev(kind, l, "pci_dss_12_3_3")))
                    .status
                    .success(),
                "{l} on {kind}"
            );
        }
    }
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=0"));
}

#[test]
fn cl3_unknown_control_codes_are_refused() {
    let d = dir("cl3");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for c in [
        "pci_dss_10_3_3",
        "nist_800_53_au_11",
        "dora_rts_art_99",
        "soc2_cc7_2",
    ] {
        assert!(
            !run(
                &["log-evidence", ds],
                Some(&ev("evidence.control_check", "crypto_inventory", c))
            )
            .status
            .success(),
            "{c}"
        );
    }
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=0"));
}

#[test]
fn cl4_the_old_labels_still_work_with_an_old_control() {
    let d = dir("cl4");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    assert!(run(
        &["log-evidence", ds],
        Some(&ev("evidence.control_check", "ci_tests", "hipaa_164_312_b"))
    )
    .status
    .success());
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=1"));
}
