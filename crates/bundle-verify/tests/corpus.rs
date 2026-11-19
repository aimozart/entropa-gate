//! BV1: `verify_bytes` gives, for every case of the browser corpus, the verdict frozen in the manifest by the native verifier, with the closed codes; the oversize and 16 MB cases are refused as LIMIT; a tampered bundle is never accepted. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_bundle_verify::{verify_bytes, INVALID, LIMIT, OK, VERIFY};
use serde_json::Value;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ledger/tests/bundle_corpus")
}

fn manifest() -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir().join("manifest.json")).unwrap()).unwrap()
}

fn code_of(class: &str) -> i32 {
    match class {
        "ok" => OK,
        "Invalid" => INVALID,
        "Verify" => VERIFY,
        "Limit" => LIMIT,
        other => panic!("unknown class {other}"),
    }
}

/// The case files are generated at test time by the ledger test (CORPUS_EXPORT); this test reads them from a directory named by BV1_CORPUS_DIR.
fn bytes(id: &str, c: &Value) -> Vec<u8> {
    if let Some(g) = c.get("generate") {
        return format!(
            "{{\"pad\":\"{}\"}}",
            "x".repeat(g["pad_bytes"].as_u64().unwrap() as usize)
        )
        .into_bytes();
    }
    let d = std::env::var("BV1_CORPUS_DIR")
        .expect("BV1_CORPUS_DIR: the directory written by CORPUS_EXPORT");
    std::fs::read(PathBuf::from(d).join(format!("{id}.json"))).unwrap()
}

#[test]
#[ignore = "needs BV1_CORPUS_DIR (written by `CORPUS_EXPORT=DIR cargo test -p entropa-ledger --test bundle_corpus`); scripts/bv1-build.sh runs it with --include-ignored"]
fn b1_every_corpus_case_has_the_native_verdict_as_a_closed_code() {
    let m = manifest();
    let cases = m["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 38);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let want = code_of(c["verdict"]["class"].as_str().unwrap());
        let (code, json) = verify_bytes(&bytes(id, c));
        assert_eq!(code, want, "case {id}");
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["code"], want, "case {id}: the JSON carries the same code");
        if want == OK {
            for k in [
                "records",
                "checkpoints",
                "receipts",
                "consistency",
                "witnesses",
                "signatures",
            ] {
                assert_eq!(v[k], c["verdict"][k], "case {id}: {k}");
            }
        }
    }
}

#[test]
fn b2_a_16_mib_input_is_refused_as_limit_and_nothing_is_echoed() {
    let big = format!("{{\"pad\":\"{}\"}}", "x".repeat(16 * 1024 * 1024));
    let (code, json) = verify_bytes(big.as_bytes());
    assert_eq!(code, LIMIT);
    assert!(!json.contains("xxxx"), "no input text in the verdict");
}

#[test]
fn b3_bytes_that_are_not_text_are_invalid_not_a_crash() {
    for b in [&[0xffu8, 0xfe, 0x00][..], &[][..], b"{"] {
        let (code, _) = verify_bytes(b);
        assert_eq!(code, INVALID);
    }
}
