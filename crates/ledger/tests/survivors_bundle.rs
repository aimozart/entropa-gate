//! AT2 task 1 (the 5 open H1.2 survivors in `bundle.rs`). Killed here: `verify_bundle` line 468, the record signature check: a record whose payload carries a
//! signature that does not verify must be refused AT THAT CHECK ("record signature"), not by some later one. Argued equivalent or unreachable (a stage record (not published)):
//! `export_bundle` 245 and `verify_bundle` 516 (they concern a checkpoint of size 0 or two checkpoints of equal size: the store never writes a size-0 checkpoint and a proof between equal
//! sizes is empty either way), and `export_bundle` 294 (`text.len() > 5 MiB` at exactly 5 MiB would need a store of tens of thousands of records; listed as a gap, not constructed).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_ledger::*;
use serde_json::{json, Value};

#[test]
fn s1_a_record_signature_that_does_not_verify_is_refused_at_the_signature_check() {
    let (_, _, _, bundle) = run_mem(25, 15);
    must(verify_bundle(&bundle));
    let mut v: Value = serde_json::from_str(&bundle).unwrap();
    for idx in [0usize, 3, 7] {
        let mut w = v.clone();
        let mut bytes = hex::decode(w["records"][idx]["record_hex"].as_str().unwrap()).unwrap();
        let needle = b"\"sig\":\"";
        let at = bytes
            .windows(needle.len())
            .position(|x| x == needle)
            .expect("a signed event payload")
            + needle.len();
        bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
        w["records"][idx]["record_hex"] = json!(hex::encode(&bytes));
        let e = verify_bundle(&w.to_string())
            .expect_err("a bundle with a bad record signature must not verify");
        let text = format!("{e:?}");
        assert!(
            text.contains("record signature"),
            "record {idx}: refused, but not by the signature check: {text}"
        );
    }
    v["records"][0]["record_hex"] = v["records"][0]["record_hex"].clone();
    must(verify_bundle(&v.to_string()));
}

#[test]
fn s2_a_summary_that_differs_alone_is_refused_at_the_summary_check() {
    // kind, tenant, handle and ts all match; ONLY the summary differs: the chain of `||` must still refuse it (a `&&` in the chain accepted this)
    let (_, _, _, bundle) = run_mem(25, 15);
    let v: Value = serde_json::from_str(&bundle).unwrap();
    for idx in [0usize, 3, 7] {
        let mut w = v.clone();
        let old = w["records"][idx]["summary"].clone();
        w["records"][idx]["summary"] = json!(format!("{old} (edited)"));
        let e = verify_bundle(&w.to_string()).expect_err("a changed summary must not verify");
        let text = format!("{e:?}");
        assert!(
            text.contains("summary does not match"),
            "record {idx}: refused, but not by the summary check: {text}"
        );
    }
}
