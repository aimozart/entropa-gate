//! The serverless ingest: the same logic over HTTP. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const REQ: &str = r#"{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"How many claims were denied by payer?","output":"SELECT payer_id FROM platinum_denials_by_payer LIMIT 10","run_id":"run-http-1","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":1,"cost_micro_usd":1}"#;

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_entropa-platinum")
}

fn start(name: &str, stale_lock: bool) -> Server {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("srv-{name}-{}-{nanos}", std::process::id()));
    assert!(Command::new(exe())
        .args(["init", dir.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    if stale_lock {
        std::fs::write(dir.join("ledger").join(".lock"), b"").unwrap();
    }
    // A free port is found by binding port 0 and closing the listener, so another test of this file (they run in parallel) can be handed the same port before our server binds it:
    // the readiness probe would then connect to THEIR server, and later requests fail ("connection refused") when it goes away. So: after the probe succeeds, wait a moment and
    // check that OUR child is still running; if it exited (it could not bind), choose another port and start again (at most 5 attempts).
    for _attempt in 0..5 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut child = Command::new(exe())
            .args(["serve", dir.to_str().unwrap()])
            .env("PORT", port.to_string())
            .env("BIND", "127.0.0.1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut up = false;
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                up = true;
                break;
            }
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if up {
            std::thread::sleep(Duration::from_millis(150));
            if child.try_wait().ok().flatten().is_none() {
                return Server { child, port, dir };
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    panic!("server did not start");
}

fn http(s: &Server, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}", body.len());
    c.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    let code = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = out.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (code, body)
}

#[test]
fn s1_health_log_verify_over_http() {
    let s = start("s1", false);
    assert_eq!(http(&s, "GET", "/healthz", "").0, 200);
    for _ in 0..2 {
        let (c, b) = http(&s, "POST", "/v1/decision", REQ);
        assert_eq!(c, 200, "{b}");
        assert!(b.contains("subject_hash"));
    }
    let (c, b) = http(&s, "GET", "/v1/verify", "");
    assert_eq!(c, 200);
    assert!(b.contains("OK records=2 checkpoints=2"), "{b}");
    // the CLI sees the same ledger
    let o = Command::new(exe())
        .args(["verify", s.dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("OK records=2"));
}

#[test]
fn s2_bad_requests_get_4xx_and_write_nothing() {
    let s = start("s2", false);
    assert_eq!(http(&s, "POST", "/v1/decision", "not json").0, 400);
    assert_eq!(
        http(
            &s,
            "POST",
            "/v1/decision",
            &REQ.replace("nl_query", "fraud_screen")
        )
        .0,
        400
    );
    assert_eq!(http(&s, "GET", "/nope", "").0, 404);
    assert_eq!(http(&s, "GET", "/v1/decision", "").0, 405);
    let (_, b) = http(&s, "GET", "/v1/verify", "");
    assert!(b.contains("OK records=0"), "{b}");
}

#[test]
fn s3_an_oversized_body_is_refused() {
    let s = start("s3", false);
    let big = format!(r#"{{"input":"{}"}}"#, "x".repeat(3 * 1024 * 1024));
    let (c, _) = http(&s, "POST", "/v1/decision", &big);
    assert!(c == 413 || c == 400, "{c}");
}

#[test]
fn s4_a_stale_lock_from_a_crashed_instance_is_cleared_at_boot() {
    let s = start("s4", true);
    assert_eq!(http(&s, "POST", "/v1/decision", REQ).0, 200);
}

#[test]
fn s5_errors_never_echo_the_request() {
    let s = start("s5", false);
    let bad = REQ.replace(
        "How many claims",
        &format!("ssn {}-{}-{}", "123", "45", "6789"),
    );
    let (c, b) = http(&s, "POST", "/v1/decision", &bad);
    assert_eq!(c, 400);
    assert!(!b.contains("6789") && !b.contains("denied"));
}

#[test]
fn s6_the_public_key_is_served_and_matches_the_cli() {
    let s = start("s6", false);
    let (c, b) = http(&s, "GET", "/v1/pubkey", "");
    assert_eq!(c, 200);
    let o = Command::new(exe())
        .args(["pubkey", s.dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(b.trim(), String::from_utf8_lossy(&o.stdout).trim());
}

const EV: &str = r#"{"kind":"evidence.control_check","label":"rls_test","decision":"allow","reason":"check_passed","control":"hipaa_164_312_a1","total":25,"passed":25,"flagged":0,"detail":"wrong-actor queries returned zero rows","run_id":"run-rls-1"}"#;

#[test]
fn s7_the_evidence_endpoint_logs_and_verifies_over_http() {
    let s = start("s7", false);
    let (c, b) = http(&s, "POST", "/v1/evidence", EV);
    assert_eq!(c, 200, "{b}");
    assert!(b.contains("subject_hash"));
    assert_eq!(http(&s, "POST", "/v1/evidence", "not json").0, 400);
    assert_eq!(
        http(
            &s,
            "POST",
            "/v1/evidence",
            &EV.replace("rls_test", "silver")
        )
        .0,
        400
    );
    let (c, b) = http(&s, "GET", "/v1/evidence/verify", "");
    assert_eq!(c, 200);
    assert!(b.contains("OK records=1 checkpoints=1"), "{b}");
    // the AI-decision ledger is separate
    assert!(http(&s, "GET", "/v1/verify", "").1.contains("OK records=0"));
}

#[test]
fn s8_both_ledgers_export_a_bundle_with_plain_english_and_no_raw_text() {
    let s = start("s8", false);
    assert_eq!(http(&s, "POST", "/v1/decision", REQ).0, 200);
    assert_eq!(http(&s, "POST", "/v1/evidence", EV).0, 200);
    let (c, b) = http(&s, "GET", "/v1/export", "");
    assert_eq!(c, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert!(v["verified"].as_str().unwrap().starts_with("OK records=1"));
    let r = &v["records"][0];
    assert_eq!(r["kind"], "platinum.decision");
    assert!(r["plain"].as_str().unwrap().contains("SQL guard"), "{r}");
    assert_eq!(r["model_id"], "gemini-3.8-flash");
    assert_eq!(r["subject_hash"].as_str().unwrap().len(), 64);
    assert!(!b.contains("denied by payer") && !b.contains("run-http-1"));
    let (c, b) = http(&s, "GET", "/v1/evidence/export", "");
    assert_eq!(c, 200);
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert!(v["records"][0]["plain"]
        .as_str()
        .unwrap()
        .contains("Row-level security"));
    assert!(!b.contains("wrong-actor"));
}
