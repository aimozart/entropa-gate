//! The audit-evidence ledger on the node: a second ledger beside the AI-decision ledger. Synthetic only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ev-{name}-{}-{nanos}", std::process::id()))
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

const RUN: &str = r#"{"kind":"evidence.pipeline_run","label":"silver","decision":"allow","reason":"check_passed","control":"hipaa_164_312_c1","total":7000,"passed":6210,"flagged":790,"detail":"night=2026-11-05 layer=silver valid+quarantine=input","run_id":"run-2026-11-05-s"}"#;
const CHECK: &str = r#"{"kind":"evidence.control_check","label":"rls_test","decision":"allow","reason":"check_passed","control":"hipaa_164_312_a1","total":25,"passed":25,"flagged":0,"detail":"wrong-actor queries returned zero rows","run_id":"run-rls-1"}"#;

#[test]
fn ec1_log_and_verify_a_separate_evidence_ledger() {
    let d = dir("ec1");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for r in [RUN, CHECK] {
        let o = run(&["log-evidence", ds], Some(r));
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert!(out(&o).contains("subject_hash"));
    }
    let v = run(&["verify-evidence", ds], None);
    assert!(
        out(&v).contains("OK records=2 checkpoints=2"),
        "{}",
        out(&v)
    );
    // the AI-decision ledger is untouched
    assert!(out(&run(&["verify", ds], None)).contains("OK records=0"));
}

#[test]
fn ec2_bad_requests_are_refused_and_nothing_is_written() {
    let d = dir("ec2");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    let ssn = format!("patient {}-{}-{}", "123", "45", "6789");
    let bad = [
        "not json".to_string(),
        r#"{"kind":"evidence.pipeline_run"}"#.to_string(),
        RUN.replace("evidence.pipeline_run", "tx.screened"),
        RUN.replace("\"silver\"", "\"rls_test\""),
        RUN.replace("\"passed\":6210", "\"passed\":9999"),
        RUN.replace("hipaa_164_312_c1", "made_up_control"),
        RUN.replace("night=2026-11-05", &ssn),
        RUN.replace('}', ",\"extra\":1}"),
    ];
    for b in &bad {
        assert!(
            !run(&["log-evidence", ds], Some(b)).status.success(),
            "accepted: {b}"
        );
    }
    assert!(out(&run(&["verify-evidence", ds], None)).contains("OK records=0"));
}

#[test]
fn ec3_the_detail_text_never_reaches_disk() {
    let d = dir("ec3");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    assert!(run(&["log-evidence", ds], Some(RUN)).status.success());
    let mut stack = vec![d.clone()];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(p).unwrap() {
            let e = e.unwrap().path();
            if e.is_dir() {
                stack.push(e);
            } else if e.file_name().unwrap() != "platinum.key" {
                let s = String::from_utf8_lossy(&std::fs::read(&e).unwrap()).to_string();
                let decoded: Vec<u8> = s
                    .lines()
                    .filter_map(|l| hex::decode(l).ok())
                    .flatten()
                    .collect();
                let dec = String::from_utf8_lossy(&decoded).to_string();
                for needle in ["valid+quarantine", "night=2026"] {
                    assert!(
                        !s.contains(needle) && !dec.contains(needle),
                        "{needle} in {e:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn ec4_a_tampered_evidence_record_is_detected() {
    let d = dir("ec4");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    run(&["log-evidence", ds], Some(RUN));
    run(&["log-evidence", ds], Some(CHECK));
    let f = d.join("evidence-ledger").join("records.log");
    let mut lines: Vec<String> = std::fs::read_to_string(&f)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let mut b = hex::decode(&lines[0]).unwrap();
    let n = b.len();
    b[n - 5] ^= 1;
    lines[0] = hex::encode(b);
    std::fs::write(&f, lines.join("\n") + "\n").unwrap();
    assert!(!run(&["verify-evidence", ds], None).status.success());
}

#[test]
fn ex1_the_export_bundle_lists_records_hashes_and_checkpoints_without_detail() {
    let d = dir("ex1");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    run(&["log-evidence", ds], Some(RUN));
    run(&["log-evidence", ds], Some(CHECK));
    let o = run(&["export-evidence", ds], None);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let b: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(b["v"], 1);
    assert!(b["verified"]
        .as_str()
        .unwrap()
        .starts_with("OK records=2 checkpoints=2"));
    assert_eq!(
        b["pubkey"].as_str().unwrap().len(),
        3904,
        "ML-DSA-65 public key, hex"
    );
    let recs = b["records"].as_array().unwrap();
    assert_eq!(recs.len(), 2);
    let r0 = &recs[0];
    assert_eq!(r0["index"], 0);
    assert_eq!(r0["kind"], "evidence.pipeline_run");
    assert_eq!(r0["label"], "silver");
    assert_eq!(r0["control"], "hipaa_164_312_c1");
    assert_eq!(
        (
            r0["total"].as_u64(),
            r0["passed"].as_u64(),
            r0["flagged"].as_u64()
        ),
        (Some(7000), Some(6210), Some(790))
    );
    assert_eq!(r0["subject_hash"].as_str().unwrap().len(), 64);
    assert_eq!(r0["leaf_hash"].as_str().unwrap().len(), 64);
    assert!(r0["sig_prefix"].as_str().unwrap().len() <= 32);
    let cps = b["checkpoints"].as_array().unwrap();
    assert_eq!(cps.len(), 2);
    assert_eq!(cps[1]["size"], 2);
    assert_eq!(cps[1]["root"].as_str().unwrap().len(), 64);
    // nothing but codes, counts and hashes
    let text = out(&o);
    for needle in ["valid+quarantine", "night=2026", "wrong-actor", "run-2026"] {
        assert!(!text.contains(needle), "{needle} leaked into the bundle");
    }
}

#[test]
fn ex2_an_export_of_a_tampered_ledger_fails() {
    let d = dir("ex2");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    run(&["log-evidence", ds], Some(RUN));
    let f = d.join("evidence-ledger").join("records.log");
    let mut lines: Vec<String> = std::fs::read_to_string(&f)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let mut b = hex::decode(&lines[0]).unwrap();
    let n = b.len();
    b[n - 5] ^= 1;
    lines[0] = hex::encode(b);
    std::fs::write(&f, lines.join("\n") + "\n").unwrap();
    assert!(!run(&["export-evidence", ds], None).status.success());
}

#[test]
fn ex3_every_exported_record_carries_a_plain_english_sentence() {
    let d = dir("ex3");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    run(&["log-evidence", ds], Some(RUN));
    run(&["log-evidence", ds], Some(CHECK));
    let b: serde_json::Value =
        serde_json::from_str(&out(&run(&["export-evidence", ds], None))).unwrap();
    let recs = b["records"].as_array().unwrap();
    let p0 = recs[0]["plain"].as_str().unwrap();
    assert!(
        p0.contains("7,000 rows came in") && p0.contains("integrity check passed"),
        "{p0}"
    );
    let p1 = recs[1]["plain"].as_str().unwrap();
    assert!(p1.contains("Row-level security"), "{p1}");
    assert!(!p0.contains("run-2026") && !p1.contains("wrong-actor"));
}

#[test]
fn ex4_the_bundle_carries_everything_a_browser_needs_to_verify_independently() {
    use entropa_core::merkle::leaf_hash;
    let d = dir("ex4");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    run(&["log-evidence", ds], Some(RUN));
    run(&["log-evidence", ds], Some(CHECK));
    let b: serde_json::Value =
        serde_json::from_str(&out(&run(&["export-evidence", ds], None))).unwrap();
    for r in b["records"].as_array().unwrap() {
        let rec = hex::decode(r["record_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex::encode(leaf_hash(&rec)),
            r["leaf_hash"].as_str().unwrap(),
            "leaf hash = BLAKE3(0x00 || record)"
        );
        let payload: serde_json::Value =
            serde_json::from_str(r["payload"].as_str().unwrap()).unwrap();
        assert_eq!(
            payload["sig"].as_str().unwrap().len(),
            3309 * 2,
            "the full signature is in the payload"
        );
        assert!(payload.get("detail").is_none());
    }
    let cp = &b["checkpoints"][1];
    assert_eq!(
        cp["signature"].as_str().unwrap().len(),
        3309 * 2,
        "checkpoints carry the full signature"
    );
}
