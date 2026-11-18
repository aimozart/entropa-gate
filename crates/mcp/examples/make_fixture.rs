//! Builds a synthetic demo log and sample tool arguments for the real-client test
//! (docs/REAL-CLIENT-TEST.md). Usage: `make_fixture <output dir>`.
//! All data is synthetic. Keys are thrown away after signing: only public keys are written.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_core::transparency_log::{encode_record, TransparencyLog};
use entropa_core::Probe;
use serde_json::json;
use std::path::Path;

fn write(dir: &Path, name: &str, v: &serde_json::Value) {
    std::fs::write(dir.join(name), serde_json::to_string_pretty(v).unwrap()).unwrap();
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: make_fixture <output dir>");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();

    let trusted = Probe::spawn();
    let stranger = Probe::spawn();
    let mut log = TransparencyLog::new();
    let events = [
        ("agent-run-started", "event"),
        ("tool-call-approved", "approval"),
        ("deploy-requested", "request"),
        ("deploy-denied", "approval"),
        ("agent-run-finished", "event"),
    ];
    for (payload, label) in events {
        log.append(&encode_record(payload, Some(label)).unwrap());
    }
    let head = log.checkpoint(&trusted, 1_700_000_000);
    let records: Vec<String> = (0..log.len())
        .map(|i| hex::encode(log.receipt(i, &head).unwrap().record))
        .collect();

    write(
        dir,
        "log.json",
        &json!({"checkpoint": &head, "records": records}),
    );
    std::fs::write(dir.join("trusted_pubkey.txt"), trusted.pubkey_hex()).unwrap();

    let receipt = serde_json::to_value(log.receipt(2, &head).unwrap()).unwrap();
    write(dir, "receipt-valid.json", &json!({"receipt": receipt}));

    let mut tampered = receipt.clone();
    tampered["record"] = json!(hex::encode(
        encode_record("deploy-approved", Some("approval")).unwrap()
    ));
    write(dir, "receipt-tampered.json", &json!({"receipt": tampered}));

    let mut wrong_index = receipt.clone();
    wrong_index["index"] = json!(3);
    write(
        dir,
        "receipt-wrong-index.json",
        &json!({"receipt": wrong_index}),
    );

    let other_head = log.checkpoint(&stranger, 1_700_000_000);
    let untrusted = serde_json::to_value(log.receipt(2, &other_head).unwrap()).unwrap();
    write(
        dir,
        "receipt-untrusted-signer.json",
        &json!({"receipt": untrusted}),
    );

    write(dir, "checkpoint-valid.json", &json!({"checkpoint": &head}));
    let mut bad_cp = serde_json::to_value(&head).unwrap();
    bad_cp["size"] = json!(head.size + 1);
    write(
        dir,
        "checkpoint-tampered.json",
        &json!({"checkpoint": bad_cp}),
    );
    let mut upper = serde_json::to_value(&head).unwrap();
    upper["root"] = json!(hex::encode(head.root).to_uppercase());
    write(
        dir,
        "checkpoint-uppercase-hex.json",
        &json!({"checkpoint": upper}),
    );

    println!("wrote fixtures to {}", dir.display());
    println!(
        "trusted key id: {}",
        entropa_mcp::key_id(&trusted.pubkey_hex())
    );
    println!(
        "log size: {}  head root: {}",
        head.size,
        hex::encode(head.root)
    );
}
