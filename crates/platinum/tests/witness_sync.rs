//! The node sends its checkpoints to witnesses and keeps their signed statements. Real witness service in-process.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::{CheckpointSigner, Probe};
use entropa_platinum::{export_decisions, init, log_with, sync_witnesses};
use entropa_witness::verify_statement;
use entropa_witnessd::{app, FileStateStore, WitnessConfig};
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ws-{name}-{}-{nanos}", std::process::id()))
}

const DEC: &str = r#"{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"q","output":"a","run_id":"run-N","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":1,"cost_micro_usd":1}"#;

fn witness(log_pubkey: &str, state: &std::path::Path) -> (String, String) {
    let key = Probe::from_signing_key_hex(&"c4".repeat(32)).unwrap();
    let wpk = key.pubkey_hex();
    let router = app(
        WitnessConfig {
            logs: vec![(log_pubkey.to_string(), true)],
        },
        FileStateStore::open(state).unwrap(),
        Box::new(key),
    )
    .unwrap();
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
                .unwrap()
        });
    });
    (format!("http://127.0.0.1:{port}"), wpk)
}

fn log_n(d: &std::path::Path, signer: &dyn CheckpointSigner, from: usize, n: usize) {
    for i in from..from + n {
        log_with(d, signer, &DEC.replace("run-N", &format!("run-{i}"))).unwrap();
    }
}

#[test]
fn s1_a_checkpoint_is_witnessed_and_the_statement_is_kept_and_verifies() {
    let d = tmp("s1");
    init(&d).unwrap();
    let signer = Probe::from_signing_key_hex(&"7e".repeat(32)).unwrap();
    let (url, wpk) = witness(&signer.pubkey_hex(), &tmp("s1w"));
    log_n(&d, &signer, 0, 3);
    let r = sync_witnesses(&d, "ledger", std::slice::from_ref(&url));
    assert!(r[0].is_ok(), "{r:?}");
    let lines = std::fs::read_to_string(d.join("ledger").join("witness-statements.jsonl")).unwrap();
    let st = verify_statement(lines.lines().next().unwrap(), &wpk).unwrap();
    assert_eq!(st.fields.size, 3);
}

#[test]
fn s2_a_later_sync_sends_a_consistency_proof_and_names_the_previous_checkpoint() {
    let d = tmp("s2");
    init(&d).unwrap();
    let signer = Probe::from_signing_key_hex(&"7e".repeat(32)).unwrap();
    let (url, wpk) = witness(&signer.pubkey_hex(), &tmp("s2w"));
    log_n(&d, &signer, 0, 3);
    assert!(sync_witnesses(&d, "ledger", std::slice::from_ref(&url))[0].is_ok());
    log_n(&d, &signer, 3, 4);
    assert!(sync_witnesses(&d, "ledger", std::slice::from_ref(&url))[0].is_ok());
    // a second sync with nothing new does nothing and is not an error
    assert!(sync_witnesses(&d, "ledger", &[url])[0].is_ok());
    let lines: Vec<String> =
        std::fs::read_to_string(d.join("ledger").join("witness-statements.jsonl"))
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
    assert_eq!(lines.len(), 2);
    let st = verify_statement(&lines[1], &wpk).unwrap();
    assert_eq!((st.fields.size, st.fields.previous_size), (7, 3));
}

#[test]
fn s3_the_export_carries_the_witness_statements() {
    let d = tmp("s3");
    init(&d).unwrap();
    let signer = Probe::from_signing_key_hex(&"7e".repeat(32)).unwrap();
    let (url, wpk) = witness(&signer.pubkey_hex(), &tmp("s3w"));
    log_n(&d, &signer, 0, 2);
    sync_witnesses(&d, "ledger", &[url]);
    // the export uses the node signer, so run it with the same key as the node's key file for this test
    // Test change (KEYS1): init creates decisions.key, which wins over a legacy platinum.key; the test overwrites decisions.key with the same key.
    std::fs::write(d.join("decisions.key"), format!("{}\n", "7e".repeat(32))).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        d.join("decisions.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let b = export_decisions(&d).unwrap();
    let w = b["witnesses"].as_array().unwrap();
    assert_eq!(w.len(), 1);
    assert_eq!(w[0]["witness_pubkey"].as_str().unwrap(), wpk);
    assert!(verify_statement(w[0]["statement"].as_str().unwrap(), &wpk).is_ok());
}

#[test]
fn s4_an_unreachable_witness_is_reported_and_never_breaks_the_ledger() {
    let d = tmp("s4");
    init(&d).unwrap();
    let signer = Probe::from_signing_key_hex(&"7e".repeat(32)).unwrap();
    log_n(&d, &signer, 0, 2);
    let r = sync_witnesses(&d, "ledger", &["http://127.0.0.1:9".to_string()]);
    assert!(r[0].is_err());
    assert!(
        !r[0].as_ref().unwrap_err().contains("127.0.0.1:9/v1"),
        "errors never echo request details"
    );
    assert!(entropa_platinum::verify_with(&d, &signer.pubkey_hex())
        .unwrap()
        .starts_with("OK records=2"));
}
