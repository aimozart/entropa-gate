//! BROWSER-CORPUS (a stage record (not published)): freeze the native `verify_bundle` verdicts of a tampering corpus so a later browser (WASM) verifier can be held to the same answers.
//! Regenerate with `CORPUS_WRITE=1` (writes `tests/bundle_corpus/`); the normal run checks the committed files against the manifest and the native verdicts. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_ledger::*;
use serde_json::{json, Value};
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bundle_corpus")
}
fn fnv(b: &[u8]) -> String {
    // a stable fingerprint of the bytes with no new dependency (blake3 is a normal dependency of the crate)
    blake3::hash(b).to_hex().to_string()
}
fn parsed(b: &str) -> Value {
    serde_json::from_str(b).unwrap()
}
fn flip_hex(h: &str, at: usize) -> String {
    let mut b = h.as_bytes().to_vec();
    b[at] = if b[at] == b'0' { b'1' } else { b'0' };
    String::from_utf8(b).unwrap()
}

/// (case id, file text). Deterministic: fixed seeds and a fixed start time.
fn cases() -> Vec<(String, String)> {
    let small = run_mem(21, 1).3;
    let medium = run_mem(25, 15).3;
    // the tamper cases are made from the SMALL bundle (the corpus must stay small); the medium bundle is one valid case
    let base = small.clone();
    let mut out: Vec<(String, String)> = vec![
        ("valid-small".into(), small.clone()),
        ("valid-medium".into(), medium.clone()),
    ];
    let tamper = |name: &str, f: &dyn Fn(&mut Value)| {
        let mut v = parsed(&base);
        f(&mut v);
        (format!("tamper-{name}"), v.to_string())
    };
    out.push(tamper("record-byte", &|v| {
        let h = v["records"][3]["record_hex"].as_str().unwrap().to_string();
        v["records"][3]["record_hex"] = json!(flip_hex(&h, h.len() - 1));
    }));
    out.push(tamper("head-root", &|v| {
        v["head"]["root"] = json!("ab".repeat(32))
    }));
    out.push(tamper("head-size", &|v| v["head"]["size"] = json!(1)));
    out.push(tamper("checkpoint-signature-short", &|v| {
        v["checkpoints"][0]["signature"] = json!("00".repeat(10))
    }));
    out.push(tamper("receipt-dropped", &|v| {
        v["receipts"].as_array_mut().unwrap().pop();
    }));
    out.push(tamper("receipt-swapped", &|v| {
        v["receipts"].as_array_mut().unwrap().swap(0, 1)
    }));
    out.push(tamper("consistency-dropped", &|v| {
        v["consistency"].as_array_mut().unwrap().pop();
    }));
    out.push(tamper("witness-size", &|v| {
        let s = v["witnesses"][0]
            .as_str()
            .unwrap()
            .replacen("\"size\":", "\"size\":9", 1);
        v["witnesses"][0] = json!(s);
    }));
    out.push(tamper("handle-internal-name", &|v| {
        v["records"][0]["handle"] = json!("kcops".chars().rev().collect::<String>())
    }));
    out.push(tamper("actor-key-swapped", &|v| {
        let i = v["actors"]
            .as_array()
            .unwrap()
            .iter()
            .position(|a| a["pubkey_hex"] != "")
            .unwrap();
        v["actors"][i]["pubkey_hex"] = json!("ab".repeat(1952));
    }));
    out.push(tamper("synthetic-false", &|v| {
        v["synthetic"] = json!(false)
    }));
    out.push(tamper("unknown-top-level-field", &|v| {
        v["extra"] = json!(1)
    }));
    out.push(tamper("log-key-replaced", &|v| {
        v["log"]["pubkey_hex"] = json!("cd".repeat(1952))
    }));
    // one hex character flipped in each record of the small bundle, and in each checkpoint signature
    let n = parsed(&small)["records"].as_array().unwrap().len();
    for i in 0..n {
        let mut v = parsed(&small);
        let h = v["records"][i]["record_hex"].as_str().unwrap().to_string();
        v["records"][i]["record_hex"] = json!(flip_hex(&h, h.len() / 2));
        out.push((format!("flip-record-{i:02}"), v.to_string()));
    }
    let m = parsed(&small)["checkpoints"].as_array().unwrap().len();
    for i in 0..m {
        let mut v = parsed(&small);
        let s = v["checkpoints"][i]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        v["checkpoints"][i]["signature"] = json!(flip_hex(&s, s.len() / 2));
        out.push((format!("flip-checkpoint-signature-{i:02}"), v.to_string()));
    }
    for pct in [25usize, 50, 90] {
        let cut = small.len() * pct / 100;
        out.push((format!("truncated-{pct}"), small[..cut].to_string()));
    }
    out.push((
        "duplicate-top-level-key".into(),
        medium.replacen("{", "{\"head\":null,", 1),
    ));
    out.push((
        "nesting-300".into(),
        format!("{}{}", "[".repeat(300), "]".repeat(300)),
    ));
    for (name, text) in [
        ("empty-string", ""),
        ("open-brace", "{"),
        ("empty-array", "[]"),
        ("null", "null"),
        ("number", "42"),
    ] {
        out.push((format!("malformed-{name}"), text.to_string()));
    }
    out
}

fn verdict(text: &str) -> Value {
    let r = std::panic::catch_unwind(|| verify_bundle(text));
    match r {
        Err(_) => json!({"class": "PANIC"}),
        Ok(Ok(rep)) => {
            json!({"class": "ok", "records": rep.records, "checkpoints": rep.checkpoints, "receipts": rep.receipts, "consistency": rep.consistency, "witnesses": rep.witnesses, "signatures": rep.signatures})
        }
        Ok(Err(LedgerError::Invalid(_))) => json!({"class": "Invalid"}),
        Ok(Err(LedgerError::Verify(_))) => json!({"class": "Verify"}),
        Ok(Err(LedgerError::Limit(_))) => json!({"class": "Limit"}),
        Ok(Err(other)) => json!({"class": format!("OTHER:{other:?}")}),
    }
}

fn build_manifest() -> (Value, Vec<(String, String)>) {
    let cs = cases();
    let mut entries = vec![];
    for (id, text) in &cs {
        entries.push(json!({"id": id, "file": format!("{id}.json"), "sha256_blake3": fnv(text.as_bytes()), "bytes": text.len(), "verdict": verdict(text)}));
    }
    entries.push(json!({"id": "oversize-generated", "generate": {"pad_bytes": MAX_BUNDLE_BYTES + 1}, "verdict": verdict(&format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_BUNDLE_BYTES)))}));
    (
        json!({"schema": "bundle-corpus-1", "hash": "blake3 hex of the file bytes", "cases": entries}),
        cs,
    )
}

#[test]
fn k1_the_manifest_matches_a_fresh_generation() {
    // The case files are generated at test time (deterministic); only manifest.json is the frozen contract: it holds each case's hash, size and native verdict.
    // CORPUS_WRITE=1 rewrites the manifest; CORPUS_EXPORT=<dir> additionally writes the case files there (for a WASM harness).
    let (manifest, cs) = build_manifest();
    if let Some(d) = std::env::var_os("CORPUS_EXPORT") {
        std::fs::create_dir_all(&d).unwrap();
        for (id, text) in &cs {
            std::fs::write(std::path::Path::new(&d).join(format!("{id}.json")), text).unwrap();
        }
    }
    if std::env::var_os("CORPUS_WRITE").is_some() {
        std::fs::write(
            dir().join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(dir().join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(committed, manifest, "the manifest is stale or the verifier changed: regenerate with CORPUS_WRITE=1 and review the diff");
}

#[test]
fn k2_every_case_has_a_refusal_or_a_known_ok_and_none_panics() {
    let (manifest, _) = build_manifest();
    let cases = manifest["cases"].as_array().unwrap();
    assert!(cases.len() >= 35, "corpus too small: {}", cases.len()); // 38 when written; my first guess of 40 had no basis
    let mut ok = 0;
    for c in cases {
        let class = c["verdict"]["class"].as_str().unwrap();
        assert!(
            matches!(class, "ok" | "Invalid" | "Verify" | "Limit"),
            "{}: {class}",
            c["id"]
        );
        if class == "ok" {
            ok += 1;
            assert!(
                c["id"].as_str().unwrap().starts_with("valid-"),
                "an unexpected acceptance: {}",
                c["id"]
            );
        }
    }
    assert_eq!(ok, 2, "exactly the two valid bundles verify");
    // every single-character flip in a record or a checkpoint signature is refused
    for c in cases
        .iter()
        .filter(|c| c["id"].as_str().is_some_and(|i| i.starts_with("flip-")))
    {
        assert_ne!(c["verdict"]["class"], "ok", "{}", c["id"]);
    }
}

#[test]
fn k3_the_corpus_is_small_and_synthetic() {
    let (_, cs) = build_manifest();
    let total: usize = cs.iter().map(|c| c.1.len()).sum();
    assert!(total < 10_000_000, "corpus is {total} bytes");
    for (id, text) in &cs {
        let t = text.to_lowercase();
        for bad in ["private key", "begin private", "akia", "secret_key"] {
            assert!(!t.contains(bad), "{id}: {bad}");
        }
    }
}
