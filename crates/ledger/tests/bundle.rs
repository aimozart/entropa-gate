//! The static JSON bundle the front end and the WASM verifier consume.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::transparency_log::{verify_receipt, Receipt};
use entropa_ledger::*;
use proptest::prelude::*;
use serde_json::{json, Value};

fn parsed(b: &str) -> Value {
    serde_json::from_str(b).unwrap()
}

/// S7c (approved by the reviewer): bundle receipts are compact, {index, proof}. The full core Receipt is rebuilt from
/// records[i] and the head, which are already in the bundle.
fn rebuild(v: &Value, i: usize) -> Receipt {
    let entry = &v["receipts"][i];
    Receipt {
        index: entry["index"].as_u64().unwrap() as usize,
        record: hex::decode(v["records"][i]["record_hex"].as_str().unwrap()).unwrap(),
        proof: serde_json::from_value(entry["proof"].clone()).unwrap(),
        checkpoint: serde_json::from_value(v["head"].clone()).unwrap(),
    }
}

const BUNDLE_KINDS: [&str; 8] = [
    "agent.invocation",
    "tx.screened",
    "directory.actor",
    "policy.decision",
    "approval.request",
    "approval.approve",
    "approval.deny",
    "approval.consume",
];

#[test]
fn b1_the_bundle_has_the_documented_shape() {
    let (_, store, _, bundle) = run_mem(21, 20);
    let v = parsed(&bundle);
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "actors",
            "checkpoints",
            "consistency",
            "head",
            "log",
            "receipts",
            "records",
            "synthetic",
            "v",
            "witnesses"
        ]
    );
    assert_eq!(v["v"], 1);
    assert_eq!(v["synthetic"], true);
    assert_eq!(v["log"]["algorithm"], "ML-DSA-65");
    assert_eq!(v["log"]["fingerprint"].as_str().unwrap().len(), 16);
    assert_eq!(
        v["head"],
        *v["checkpoints"].as_array().unwrap().last().unwrap()
    );
    let records = v["records"].as_array().unwrap();
    assert_eq!(records.len(), store.len());
    assert_eq!(v["receipts"].as_array().unwrap().len(), records.len());
    for (i, r) in records.iter().enumerate() {
        let mut k: Vec<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
        k.sort();
        assert_eq!(
            k,
            [
                "handle",
                "index",
                "kind",
                "record_hex",
                "summary",
                "tenant",
                "ts"
            ],
            "record {i}"
        );
        assert_eq!(r["index"], i);
        assert!(BUNDLE_KINDS.contains(&r["kind"].as_str().unwrap()), "{r}");
        assert!(
            Tenant::parse(r["tenant"].as_str().unwrap()).is_some(),
            "every record has a tenant: {r}"
        );
        assert!(
            Handle::parse(r["handle"].as_str().unwrap()).is_some(),
            "every record has a public handle: {r}"
        );
        assert_eq!(
            hex::decode(r["record_hex"].as_str().unwrap()).unwrap(),
            store.record(i).unwrap()
        );
    }
    assert_eq!(
        v["consistency"].as_array().unwrap().len(),
        v["checkpoints"].as_array().unwrap().len() - 1
    );
}

#[test]
fn b2_a_fresh_bundle_verifies_and_the_counts_add_up() {
    let (_, store, summary, bundle) = run_mem(22, 25);
    let r = must(verify_bundle(&bundle));
    assert_eq!((r.records, r.receipts), (store.len(), store.len()));
    assert_eq!(
        (r.checkpoints, r.witnesses),
        (summary.checkpoints, summary.witnesses)
    );
    assert_eq!(r.consistency, summary.checkpoints - 1);
}

#[test]
fn b3_the_actors_section_uses_handles_fingerprints_and_the_attestation_chain() {
    let (g, _, _, bundle) = run_mem(23, 12);
    let v = parsed(&bundle);
    let actors = v["actors"].as_array().unwrap();
    let human = actors
        .iter()
        .find(|a| a["handle"] == "human-principal")
        .expect("the human principal is listed");
    assert_eq!(human["pubkey_hex"], "");
    assert_eq!(human["status"], "keyless");
    assert_eq!(human["attested_by"], "orchestrator-agent");
    for a in actors {
        assert!(Handle::parse(a["handle"].as_str().unwrap()).is_some());
        let id = a["key_id"].as_str().unwrap();
        assert_eq!(id.len(), 16);
        if a["pubkey_hex"] != "" {
            assert_eq!(
                entropa_approvals::key_id(a["pubkey_hex"].as_str().unwrap()),
                id
            );
        }
    }
    assert_eq!(
        actors.len(),
        g.directory().actors.len(),
        "every directory actor is listed once"
    );
    assert_eq!(v["log"]["pubkey_hex"], g.log_pubkey_hex().as_str());
}

#[test]
fn b4_no_secret_key_material_is_ever_exported() {
    let (_, _, _, bundle) = run_mem(24, 15);
    let keys = must(Keys::from_seed(24));
    for h in Handle::ALL {
        if let Some(p) = keys.probe(*h) {
            assert!(
                !bundle.contains(&p.signing_key_hex()),
                "the signing seed of {} is in the bundle",
                h.as_str()
            );
        }
    }
    let low = bundle.to_lowercase();
    for word in ["\"seed\"", "secret", "private", "signing_key"] {
        assert!(!low.contains(word), "{word} in the bundle");
    }
}

#[test]
fn b5_tampering_is_always_caught_and_never_panics() {
    let (_, _, _, bundle) = run_mem(25, 15);
    must(verify_bundle(&bundle));
    let tamper = |name: &str, f: &dyn Fn(&mut Value)| {
        let mut v = parsed(&bundle);
        f(&mut v);
        let e = verify_bundle(&v.to_string());
        match e {
            Err(LedgerError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
            Err(LedgerError::Verify(_)) | Err(LedgerError::Invalid(_)) => {}
            other => panic!("{name}: {other:?}"),
        }
    };
    tamper("record byte", &|v| {
        let h = v["records"][3]["record_hex"].as_str().unwrap().to_string();
        let flipped = if h.ends_with('0') {
            format!("{}1", &h[..h.len() - 1])
        } else {
            format!("{}0", &h[..h.len() - 1])
        };
        v["records"][3]["record_hex"] = json!(flipped);
    });
    tamper("head root", &|v| v["head"]["root"] = json!("ab".repeat(32)));
    tamper("head size", &|v| v["head"]["size"] = json!(1));
    tamper("checkpoint signature", &|v| {
        v["checkpoints"][0]["signature"] = json!("00".repeat(10))
    });
    tamper("receipt dropped", &|v| {
        v["receipts"].as_array_mut().unwrap().pop();
    });
    tamper("receipt swapped", &|v| {
        v["receipts"].as_array_mut().unwrap().swap(0, 1)
    });
    tamper("consistency dropped", &|v| {
        v["consistency"].as_array_mut().unwrap().pop();
    });
    tamper("witness size", &|v| {
        let s = v["witnesses"][0]
            .as_str()
            .unwrap()
            .replacen("\"size\":", "\"size\":9", 1);
        v["witnesses"][0] = json!(s);
    });
    tamper("handle becomes an internal name", &|v| {
        v["records"][0]["handle"] = json!("spock")
    });
    tamper("actor key swapped", &|v| {
        let i = v["actors"]
            .as_array()
            .unwrap()
            .iter()
            .position(|a| a["pubkey_hex"] != "")
            .unwrap();
        v["actors"][i]["pubkey_hex"] = json!("ab".repeat(1952));
    });
    tamper("synthetic false", &|v| v["synthetic"] = json!(false));
    tamper("unknown top-level field", &|v| v["extra"] = json!(1));
    tamper("log key replaced", &|v| {
        v["log"]["pubkey_hex"] = json!("cd".repeat(1952))
    });
    for bad in ["", "{", "[]", "null", "42"] {
        assert!(
            matches!(
                verify_bundle(bad),
                Err(LedgerError::Invalid(_)) | Err(LedgerError::NotImplemented)
            ),
            "{bad:?}"
        );
    }
    let huge = format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_BUNDLE_BYTES));
    assert!(matches!(
        verify_bundle(&huge),
        Err(LedgerError::Limit(_)) | Err(LedgerError::NotImplemented)
    ));
}

#[test]
fn b6_thirty_scenarios_fit_comfortably_under_the_size_limit() {
    // S7c (approved by the reviewer): measured 1,851,263 bytes for 30 scenarios (111 records) with compact receipts;
    // the old 100-scenario figure cannot hold with 6.6 KB hex ML-DSA signatures inside every record.
    let (_, _, _, bundle) = run_mem(26, 30);
    assert!(
        bundle.len() < MAX_BUNDLE_BYTES / 2,
        "{} bytes",
        bundle.len()
    );
}

#[test]
fn b7_the_receipts_are_bound_to_the_head_and_verify_with_the_core_verifier() {
    let (g, store, _, bundle) = run_mem(27, 12);
    let v = parsed(&bundle);
    for i in 0..v["receipts"].as_array().unwrap().len() {
        let receipt = rebuild(&v, i);
        assert_eq!(receipt.index, i);
        assert_eq!(receipt.record, store.record(i).unwrap());
        assert_eq!(
            receipt.checkpoint.size,
            store.len().max(receipt.checkpoint.size)
        );
        assert!(verify_receipt(&receipt, &g.log_pubkey_hex()), "receipt {i}");
    }
}

#[test]
fn b9_a_compact_receipt_that_points_at_another_record_or_carries_another_proof_fails() {
    let (_, _, _, bundle) = run_mem(28, 12);
    let fails = |name: &str, f: &dyn Fn(&mut Value)| {
        let mut v = parsed(&bundle);
        f(&mut v);
        match verify_bundle(&v.to_string()) {
            Err(LedgerError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
            Err(LedgerError::Verify(_)) | Err(LedgerError::Invalid(_)) => {}
            other => panic!("{name}: {other:?}"),
        }
    };
    fails("index changed to point at the next record", &|v| {
        v["receipts"][3]["index"] = json!(4)
    });
    fails("index changed to a record that does not exist", &|v| {
        v["receipts"][3]["index"] = json!(99_999)
    });
    fails("proof taken from another record", &|v| {
        let other = v["receipts"][7]["proof"].clone();
        v["receipts"][3]["proof"] = other;
    });
    fails("proof emptied", &|v| v["receipts"][5]["proof"] = json!([]));
    fails("an extra field in a compact receipt", &|v| {
        v["receipts"][2]["record"] = json!("00")
    });
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(12), failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn b8_every_exported_receipt_verifies_for_random_seeds_and_sizes(seed in 0u64..10_000, n in 1usize..9) {
        let (g, store, summary, bundle) = run_mem(seed, n);
        let report = must(verify_bundle(&bundle));
        prop_assert_eq!(report.receipts, store.len());
        prop_assert_eq!(report.records, summary.records);
        let v = parsed(&bundle);
        for i in 0..v["receipts"].as_array().unwrap().len() {
            let receipt = rebuild(&v, i);
            prop_assert!(verify_receipt(&receipt, &g.log_pubkey_hex()));
        }
    }
}
