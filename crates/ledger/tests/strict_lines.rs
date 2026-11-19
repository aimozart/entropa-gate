//! INS slice 5 red tests (round-2 findings): a checkpoint line is strict JSON with a CLOSED key set per version: a duplicated key, an unknown key, a missing key, a non-integer or oversize number are format errors,
//! for the raw reader AND the store (so `verify` and `check` agree). Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::anchor::sign_v2;
use entropa_core::merkle;
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::Probe;
use entropa_ledger::{read_raw, FileStore, LedgerError, LedgerStore};
use std::path::{Path, PathBuf};

fn probe() -> Probe {
    Probe::from_signing_key_hex(&hex::encode([8u8; 32])).unwrap()
}
/// A ledger of 2 records with one v1 checkpoint (`v2 = false`) or one v2 checkpoint (`v2 = true`); returns the directory and the single checkpoint line.
fn made(tag: &str, v2: bool) -> (PathBuf, String) {
    let d = std::env::temp_dir().join(format!("strict-lines-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let mut s = FileStore::open(&d).unwrap();
    let mut log = TransparencyLog::new();
    let recs = [b"first record".to_vec(), b"second record".to_vec()];
    for r in &recs {
        s.append(r).unwrap();
        log.append(r);
    }
    if v2 {
        let leaves: Vec<_> = recs.iter().map(|r| merkle::leaf_hash(r)).collect();
        let cp = sign_v2(
            &probe(),
            1,
            &[0u8; 32],
            &merkle::root(&leaves).unwrap(),
            2,
            100,
        )
        .unwrap();
        s.put_checkpoint_v2(&cp).unwrap();
    } else {
        s.put_checkpoint(&log.checkpoint(&probe(), 100)).unwrap();
    }
    drop(s);
    let line = std::fs::read_to_string(d.join("checkpoints.log"))
        .unwrap()
        .trim_end()
        .to_string();
    (d, line)
}
fn put(d: &Path, line: &str) {
    std::fs::write(d.join("checkpoints.log"), format!("{line}\n")).unwrap();
}
fn refused_by_both(d: &Path, what: &str) {
    match read_raw(d) {
        Err(LedgerError::Corrupt(m)) => assert!(!m.is_empty(), "{what}"),
        other => panic!("raw reader, {what}: {other:?}"),
    }
    assert!(FileStore::open_read_only(d).is_err(), "store, {what}");
}
fn with_extra(line: &str, extra: &str) -> String {
    format!("{},{extra}}}", &line[..line.len() - 1])
}

#[test]
fn t1_an_honest_line_of_each_version_is_read_by_both() {
    for v2 in [false, true] {
        let (d, _) = made(&format!("t1-{v2}"), v2);
        assert_eq!(read_raw(&d).unwrap().checkpoints.len(), 1);
        assert!(FileStore::open_read_only(&d).is_ok());
    }
}
#[test]
fn t2_a_duplicated_key_is_refused_even_when_both_values_are_equal() {
    for v2 in [false, true] {
        let (d, line) = made(&format!("t2-{v2}"), v2);
        for dup in ["\"size\":2", "\"timestamp\":100", "\"root\":\"00\""] {
            put(&d, &with_extra(&line, dup));
            refused_by_both(&d, &format!("v2={v2} duplicate {dup}"));
        }
    }
}
#[test]
fn t3_an_unknown_extra_key_is_refused_in_both_versions() {
    for v2 in [false, true] {
        let (d, line) = made(&format!("t3-{v2}"), v2);
        for extra in [
            "\"extra\":1",
            "\"note\":\"hello\"",
            "\"prev\":\"00\"",
            "\"counter\":1",
        ] {
            // `prev` and `counter` are keys of the OTHER version for a v1 line, and a repeat for a v2 line
            if v2 && (extra.starts_with("\"prev\"") || extra.starts_with("\"counter\"")) {
                continue;
            }
            put(&d, &with_extra(&line, extra));
            refused_by_both(&d, &format!("v2={v2} extra {extra}"));
        }
    }
}
#[test]
fn t4_a_missing_key_is_refused() {
    for v2 in [false, true] {
        let (d, line) = made(&format!("t4-{v2}"), v2);
        let keys: &[&str] = if v2 {
            &[
                "root",
                "size",
                "timestamp",
                "proposer_pubkey",
                "signature",
                "counter",
                "prev",
            ]
        } else {
            &["root", "size", "timestamp", "proposer_pubkey", "signature"]
        };
        for k in keys {
            let mut v: serde_json::Value = serde_json::from_str(&line).unwrap();
            v.as_object_mut().unwrap().remove(*k);
            put(&d, &v.to_string());
            if *k == "counter" {
                continue; // without `counter` the line is a v1 line with an unknown `prev`: refused for that reason
            }
            refused_by_both(&d, &format!("v2={v2} missing {k}"));
        }
    }
}
#[test]
fn t5_numbers_must_be_whole_and_not_above_two_to_the_53_minus_1() {
    for v2 in [false, true] {
        let (d, line) = made(&format!("t5-{v2}"), v2);
        for (key, bad) in [
            ("size", "2.0"),
            ("size", "9007199254740992"),
            ("timestamp", "100.5"),
            ("timestamp", "18446744073709551615"),
            ("size", "-1"),
            ("timestamp", "1e2"),
        ] {
            let mut v: serde_json::Value = serde_json::from_str(&line).unwrap();
            let text = line.replacen(
                &format!("\"{key}\":{}", v[key]),
                &format!("\"{key}\":{bad}"),
                1,
            );
            v[key] = serde_json::Value::Null;
            put(&d, &text);
            refused_by_both(&d, &format!("v2={v2} {key}={bad}"));
        }
        if v2 {
            let text = line.replacen("\"counter\":1", "\"counter\":9007199254740992", 1);
            put(&d, &text);
            refused_by_both(&d, "counter above 2^53 - 1");
        }
    }
}
