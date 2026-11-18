//! The witness service end to end over HTTP, with real files for state. All data is synthetic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::merkle::{consistency_proof, leaf_hash, Hash};
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::Probe;
use entropa_witness::{log_id_for, verify_statement};
use entropa_witnessd::{app, FileStateStore, WitnessConfig};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

fn tmp(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("wd-{name}-{}-{nanos}", std::process::id()))
}

struct Log {
    probe: Probe,
    prefix: &'static str,
    leaves: Vec<Hash>,
}
impl Log {
    fn new(seed: &str, prefix: &'static str, n: usize) -> Log {
        let probe = Probe::from_signing_key_hex(&seed.repeat(32)).unwrap();
        let leaves = (0..n)
            .map(|i| leaf_hash(format!("{prefix}-{i}").as_bytes()))
            .collect();
        Log {
            probe,
            prefix,
            leaves,
        }
    }
    fn request(&self, n: usize, old: usize) -> String {
        let mut l = TransparencyLog::new();
        for i in 0..n {
            l.append(format!("{}-{i}", self.prefix).as_bytes());
        }
        let cp = l.checkpoint(&self.probe, 1_699_999_000 + n as u64);
        let proof: Vec<String> = if old == 0 || old == n {
            vec![]
        } else {
            consistency_proof(&self.leaves[..n], old)
                .unwrap()
                .iter()
                .map(hex::encode)
                .collect()
        };
        json!({"v":1,"log_id":log_id_for(&self.probe.pubkey_hex()),"checkpoint":{"root":hex::encode(cp.root),"size":cp.size,"timestamp":cp.timestamp,"proposer_pubkey":cp.proposer_pubkey,"signature":cp.signature},"consistency":proof}).to_string()
    }
}

fn start(dir: &std::path::Path, log: &Log, allow_first: bool) -> (u16, String) {
    let witness_key = Probe::from_signing_key_hex(&"9a".repeat(32)).unwrap();
    let pubkey = witness_key.pubkey_hex();
    let cfg = WitnessConfig {
        logs: vec![(log.probe.pubkey_hex(), allow_first)],
    };
    let store = FileStateStore::open(dir).unwrap();
    let router = app(cfg, store, Box::new(witness_key)).unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            axum::serve(tokio::net::TcpListener::from_std(l).unwrap(), router)
                .await
                .unwrap();
        });
    });
    (port, pubkey)
}

fn http(port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
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
    (code, out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

#[test]
fn w1_the_first_checkpoint_is_accepted_and_the_statement_verifies() {
    let log = Log::new("1f", "rec", 5);
    let (port, wpk) = start(&tmp("w1"), &log, true);
    let (c, b) = http(port, "POST", "/v1/cosign", &log.request(3, 0));
    assert_eq!(c, 200, "{b}");
    let st = verify_statement(&b, &wpk).unwrap();
    assert_eq!(st.fields.size, 3);
    assert_eq!(http(port, "GET", "/v1/pubkey", "").1.trim(), wpk);
    assert_eq!(http(port, "GET", "/healthz", "").0, 200);
}

#[test]
fn w2_an_extension_with_a_valid_proof_is_accepted_and_names_the_previous_checkpoint() {
    let log = Log::new("1f", "rec", 8);
    let (port, wpk) = start(&tmp("w2"), &log, true);
    assert_eq!(http(port, "POST", "/v1/cosign", &log.request(3, 0)).0, 200);
    let (c, b) = http(port, "POST", "/v1/cosign", &log.request(7, 3));
    assert_eq!(c, 200, "{b}");
    let st = verify_statement(&b, &wpk).unwrap();
    assert_eq!((st.fields.size, st.fields.previous_size), (7, 3));
}

#[test]
fn w3_rollback_a_bad_proof_and_a_fork_are_refused() {
    let log = Log::new("1f", "rec", 8);
    let fork = Log {
        probe: Probe::from_signing_key_hex(&"1f".repeat(32)).unwrap(),
        prefix: "alt",
        leaves: (0..8)
            .map(|i| leaf_hash(format!("alt-{i}").as_bytes()))
            .collect(),
    };
    let dir = tmp("w3");
    let (port, _) = start(&dir, &log, true);
    assert_eq!(http(port, "POST", "/v1/cosign", &log.request(6, 0)).0, 200);
    assert_eq!(
        http(port, "POST", "/v1/cosign", &log.request(3, 0)).0,
        409,
        "rollback"
    );
    assert_eq!(
        http(port, "POST", "/v1/cosign", &fork.request(6, 0)).0,
        409,
        "same size, different root: equivocation"
    );
    // a proof that does not connect the stored checkpoint to the new one
    let mut bad: Value = serde_json::from_str(&log.request(8, 6)).unwrap();
    bad["consistency"] = json!(["00".repeat(32)]);
    assert_eq!(http(port, "POST", "/v1/cosign", &bad.to_string()).0, 409);
    let evidence: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains("equivocation"))
        .collect();
    assert_eq!(
        evidence.len(),
        1,
        "the equivocation is recorded as evidence"
    );
}

#[test]
fn w4_unknown_logs_bad_signatures_and_junk_are_refused_without_echo() {
    let log = Log::new("1f", "rec", 4);
    let stranger = Log::new("2e", "rec", 4);
    let (port, _) = start(&tmp("w4"), &log, true);
    assert_eq!(
        http(port, "POST", "/v1/cosign", &stranger.request(2, 0)).0,
        404,
        "log not configured"
    );
    let mut forged: Value = serde_json::from_str(&log.request(2, 0)).unwrap();
    forged["checkpoint"]["signature"] = json!("00".repeat(3309));
    assert_eq!(http(port, "POST", "/v1/cosign", &forged.to_string()).0, 403);
    let (c, b) = http(port, "POST", "/v1/cosign", "not json at all secret-ish");
    assert_eq!(c, 400);
    assert!(!b.contains("secret-ish"));
    let big = format!("{{\"x\":\"{}\"}}", "a".repeat(70_000));
    assert_eq!(http(port, "POST", "/v1/cosign", &big).0, 413);
    assert_eq!(http(port, "GET", "/v1/cosign", "").0, 405);
}

#[test]
fn w5_state_survives_a_restart() {
    let log = Log::new("1f", "rec", 8);
    let dir = tmp("w5");
    let (port, _) = start(&dir, &log, true);
    assert_eq!(http(port, "POST", "/v1/cosign", &log.request(4, 0)).0, 200);
    // a second service over the same directory continues from the stored checkpoint
    let (port2, wpk) = start(&dir, &log, false);
    let (c, b) = http(port2, "POST", "/v1/cosign", &log.request(8, 4));
    assert_eq!(c, 200, "{b}");
    assert_eq!(verify_statement(&b, &wpk).unwrap().fields.previous_size, 4);
    assert_eq!(
        http(port2, "POST", "/v1/cosign", &log.request(3, 0)).0,
        409,
        "and still refuses a rollback"
    );
}

#[test]
fn w6_first_checkpoints_need_allow_first() {
    let log = Log::new("1f", "rec", 4);
    let (port, _) = start(&tmp("w6"), &log, false);
    assert_eq!(http(port, "POST", "/v1/cosign", &log.request(2, 0)).0, 409);
}
