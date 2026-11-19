//! The platinum CLI end to end: init, log, verify, tamper. All data is synthetic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("plat-{name}-{}-{nanos}", std::process::id()))
}

fn run(args: &[&str], stdin: Option<&str>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_entropa-platinum"));
    c.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}

fn text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

const REQ: &str = r#"{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"How many claims were denied by payer?","output":"SELECT payer, COUNT(*) FROM platinum.denials GROUP BY payer LIMIT 100","run_id":"run-2026-11-05-s","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":120,"output_tokens":40,"cost_micro_usd":90}"#;

#[test]
fn c1_init_log_verify_round_trip() {
    let d = dir("c1");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for _ in 0..3 {
        let o = run(&["log", ds], Some(REQ));
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert!(text(&o).contains("subject_hash"));
    }
    let v = run(&["verify", ds], None);
    assert!(v.status.success(), "{}", String::from_utf8_lossy(&v.stderr));
    assert!(
        text(&v).contains("OK records=3 checkpoints=3"),
        "{}",
        text(&v)
    );
}

#[test]
fn c2_nothing_raw_reaches_disk() {
    let d = dir("c2");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    assert!(run(&["log", ds], Some(REQ)).status.success());
    for entry in walk(&d) {
        if entry.file_name().unwrap() == "platinum.key" {
            continue;
        }
        let bytes = std::fs::read(&entry).unwrap();
        let s = String::from_utf8_lossy(&bytes).to_string();
        // records are hex-encoded, so also check the decoded text of every line
        let decoded: Vec<u8> = s
            .lines()
            .filter_map(|l| hex::decode(l).ok())
            .flatten()
            .collect();
        let dec = String::from_utf8_lossy(&decoded).to_string();
        for needle in ["denied", "SELECT", "platinum.denials"] {
            assert!(
                !s.contains(needle) && !dec.contains(needle),
                "{needle} on disk in {entry:?}"
            );
        }
    }
}

fn walk(p: &std::path::Path) -> Vec<PathBuf> {
    let mut out = vec![];
    for e in std::fs::read_dir(p).unwrap() {
        let e = e.unwrap().path();
        if e.is_dir() {
            out.extend(walk(&e));
        } else {
            out.push(e);
        }
    }
    out
}

#[test]
fn c3_the_key_file_is_private_and_a_loose_one_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let d = dir("c3");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    // Test change (KEYS1): init now creates decisions.key (and evidence.key) instead of the single platinum.key; the assertions are unchanged.
    let key = d.join("decisions.key");
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = run(&["log", ds], Some(REQ));
    assert!(!o.status.success());
    assert!(!text(&o).contains(&std::fs::read_to_string(&key).unwrap().trim().to_string()));
}

#[test]
fn c4_bad_requests_are_refused_and_nothing_is_written() {
    let d = dir("c4");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    let bad = [
        "not json",
        r#"{"label":"nl_query"}"#,
        &REQ.replace("nl_query", "fraud_screen"),
        &REQ.replace("}", r#","extra":"x"}"#),
        &REQ.replace(
            "How many claims",
            &format!("ssn {}-{}-{}", "123", "45", "6789"),
        ),
    ];
    for b in bad {
        let o = run(&["log", ds], Some(b));
        assert!(!o.status.success(), "accepted: {b}");
    }
    let v = run(&["verify", ds], None);
    assert!(text(&v).contains("OK records=0"), "{}", text(&v));
}

#[test]
fn c5_tampering_with_a_record_is_detected() {
    let d = dir("c5");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    run(&["log", ds], Some(REQ));
    run(&["log", ds], Some(REQ));
    let f = d.join("ledger").join("records.log");
    let s = std::fs::read_to_string(&f).unwrap();
    let mut lines: Vec<String> = s.lines().map(str::to_string).collect();
    let mut b = hex::decode(&lines[0]).unwrap();
    let n = b.len();
    b[n - 5] ^= 1;
    lines[0] = hex::encode(b);
    std::fs::write(&f, lines.join("\n") + "\n").unwrap();
    let v = run(&["verify", ds], None);
    assert!(!v.status.success());
}

#[test]
fn c6_a_second_writer_is_refused() {
    let d = dir("c6");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    std::fs::write(d.join("ledger").join(".lock"), b"").unwrap();
    assert!(!run(&["log", ds], Some(REQ)).status.success());
}
