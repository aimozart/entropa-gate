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
    // The port is picked and released before the server binds it, so something else can take it in
    // between. start_on() checks that the answering server is ours; if not, take a new port.
    for _ in 0..10 {
        if let Ok(s) = start_on(name, stale_lock, free_port()) {
            return s;
        }
    }
    panic!("server did not start");
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start a server on `port`. Err if it never answered on that port.
fn start_on(name: &str, stale_lock: bool, port: u16) -> Result<Server, String> {
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
    let mut child = Command::new(exe())
        .args(["serve", dir.to_str().unwrap()])
        .env("PORT", port.to_string())
        .env("BIND", "127.0.0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        // Ours only if our process is still alive and the key served on the port is the key of
        // this node directory (a foreign listener cannot know it).
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        if let Some(key) = get_pubkey(port) {
            let o = Command::new(exe())
                .args(["pubkey", dir.to_str().unwrap()])
                .output()
                .unwrap();
            if key.trim() == String::from_utf8_lossy(&o.stdout).trim() && !key.trim().is_empty() {
                return Ok(Server { child, port, dir });
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("server did not start".to_string())
}

fn get_pubkey(port: u16) -> Option<String> {
    let mut c = TcpStream::connect(("127.0.0.1", port)).ok()?;
    c.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    c.write_all(b"GET /v1/pubkey HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut out = String::new();
    c.read_to_string(&mut out).ok()?;
    if !out.starts_with("HTTP/1.1 200") {
        return None;
    }
    Some(out.split("\r\n\r\n").nth(1)?.to_string())
}

fn http(s: &Server, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}", body.len());
    // A server may refuse early (413) and close while the body is still being written; the write
    // is then cut off, and the refusal that was already sent must still be read.
    let _ = c.write_all(req.as_bytes());
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

/// A server that refuses at once (413) and closes with the body unread, as the real one does at its
/// body limit. This makes the early-close ordering deterministic, so no load is needed.
fn early_refusing_server() -> Server {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let _ = c.write_all(
                b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            // dropped with the request body unread: the client's write is reset
        }
    });
    Server {
        child: Command::new("sleep").arg("30").spawn().unwrap(),
        port,
        dir: PathBuf::from("unused"),
    }
}

#[test]
fn s3b_the_client_helper_reads_an_early_refusal_even_when_its_write_is_cut_off() {
    let s = early_refusing_server();
    let big = format!(r#"{{"input":"{}"}}"#, "x".repeat(3 * 1024 * 1024));
    let (c, _) = http(&s, "POST", "/v1/decision", &big);
    assert_eq!(c, 413);
}

#[test]
fn s9_a_port_taken_by_someone_else_is_not_mistaken_for_our_server() {
    // A foreign listener took the port between "pick" and "bind" (the old pick-then-release race).
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = squatter.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in squatter.incoming().flatten() {
            let mut c = c;
            let _ =
                c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    assert!(start_on("s9", false, port).is_err());
}
