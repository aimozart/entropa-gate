//! NODECORE step 1 (a stage record (not published)): PIN the accepted append/verify behaviour of the two writers that exist today (platinum `log_with`/`verify_with` = A, gate `node::record`/`verify` = B)
//! BEFORE any code moves. These tests are GREEN on the unmoved code by design: they record what it does (bytes of the ledger files, the exact error and verify texts), so a later move can be
//! shown to change nothing. The goldens in `pins/nodecore.json` were produced by the unmoved code with `PIN_WRITE=1` (derived from the code under test: that is what a pin is). Synthetic data only;
//! the key is a fixed synthetic test seed built from a repeated byte, never a real key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_gate::node;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const GOLDEN: &str = "tests/pins/nodecore.json";

fn req(n: u32) -> String {
    format!(
        r#"{{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"synthetic question {n}","output":"SELECT {n}","run_id":"run-pin-{n}","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":{n},"output_tokens":4,"cost_micro_usd":9,"ts":{}}}"#,
        1_700_000_000 + n
    )
}
fn seed() -> String {
    format!("{:02x}", 7u8).repeat(32)
}
fn fresh(root: &Path, name: &str) -> PathBuf {
    let d = root.join(name);
    std::fs::create_dir_all(d.join("ledger")).unwrap();
    let k = d.join("platinum.key");
    std::fs::write(&k, format!("{}\n", seed())).unwrap();
    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn sha(p: &Path) -> String {
    // FNV-1a 64 plus the length: a stable fingerprint of the bytes with no new dependency (pins need equality, not collision resistance)
    let b = std::fs::read(p).unwrap_or_default();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in &b {
        h = (h ^ u64::from(*x)).wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}:{}", b.len())
}
fn ledger_hashes(d: &Path) -> BTreeMap<String, String> {
    ["records.log", "checkpoints.log"]
        .iter()
        .map(|f| (f.to_string(), sha(&d.join("ledger").join(f))))
        .collect()
}
fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let (p, q) = (e.path(), to.join(e.file_name()));
        if p.is_dir() {
            copy(&p, &q);
        } else {
            std::fs::copy(&p, &q).unwrap();
        }
    }
}
fn a_log(d: &Path, r: &str) -> Result<Value, String> {
    entropa_platinum::log_with(d, &*entropa_platinum::node_signer(d).unwrap(), r)
}
fn b_rec(d: &Path, r: &str) -> Result<String, String> {
    node::record(d, r)
        .map(|x| x.to_json())
        .map_err(|e| e.to_string())
}
fn a_ver(d: &Path) -> Result<String, String> {
    let pk = entropa_platinum::node_signer(d).unwrap().pubkey_hex();
    entropa_platinum::verify_with(d, &pk)
}
fn b_ver(d: &Path) -> Result<String, String> {
    node::verify(d).map_err(|e| e.to_string())
}

/// Everything the pins observe, as one JSON value (compared with the golden).
fn observe() -> Value {
    let t = tempfile::tempdir().unwrap();
    let (a, b) = (fresh(t.path(), "a"), fresh(t.path(), "b"));
    let mut out = serde_json::Map::new();
    // 1. receipts and file bytes after four appends through each writer
    let (mut ra, mut rb) = (vec![], vec![]);
    for n in 1..=4 {
        ra.push(a_log(&a, &req(n)).unwrap());
        rb.push(serde_json::from_str::<Value>(&b_rec(&b, &req(n)).unwrap()).unwrap());
    }
    out.insert("receipts_a".into(), json!(ra));
    out.insert("receipts_b".into(), json!(rb));
    out.insert("files_a".into(), json!(ledger_hashes(&a)));
    out.insert("files_b".into(), json!(ledger_hashes(&b)));
    out.insert("verify_a_ok".into(), json!(a_ver(&a)));
    out.insert("verify_b_ok".into(), json!(b_ver(&b)));
    out.insert("cross_a_by_b".into(), json!(b_ver(&a)));
    out.insert("cross_b_by_a".into(), json!(a_ver(&b)));
    // 2. exact error texts for bad requests, both writers, on an empty ledger (and the ledger stays empty)
    let good = req(9);
    let bads: Vec<(&str, String)> = vec![
        ("not_json", "not json".into()),
        ("not_object", "[1,2]".into()),
        ("unknown_field", good.replace("\"ts\"", "\"zzz\"")),
        ("bad_label", good.replace("nl_query", "no_such_label")),
        ("bad_decision", good.replace("\"allow\"", "\"maybe\"")),
        ("bad_reason", good.replace("guard_passed", "no_such_reason")),
        ("bad_provider", good.replace("vertex", "nobody")),
        (
            "missing_field",
            good.replace("\"run_id\":\"run-pin-9\",", ""),
        ),
        (
            "text_not_text",
            good.replace("\"input\":\"synthetic question 9\"", "\"input\":5"),
        ),
        (
            "number_not_number",
            good.replace("\"input_tokens\":9", "\"input_tokens\":\"9\""),
        ),
    ];
    let (ea, eb) = (fresh(t.path(), "ea"), fresh(t.path(), "eb"));
    let mut errs = serde_json::Map::new();
    for (name, body) in &bads {
        errs.insert(
            name.to_string(),
            json!({"a": a_log(&ea, body).unwrap_err(), "b": b_rec(&eb, body).unwrap_err()}),
        );
    }
    out.insert("errors".into(), Value::Object(errs));
    out.insert("empty_after_errors_a".into(), json!(ledger_hashes(&ea)));
    out.insert("empty_after_errors_b".into(), json!(ledger_hashes(&eb)));
    // 3. the DUPLICATE-KEY difference, pinned as it is today (decision D1 changes A later, on its own red test)
    let dup = good.replacen("\"run_id\"", "\"label\":\"nl_query\",\"run_id\"", 1);
    let (da, db) = (fresh(t.path(), "da"), fresh(t.path(), "db"));
    out.insert(
        "duplicate_key".into(),
        json!({"a": a_log(&da, &dup).map(|_| "accepted".to_string()), "b": b_rec(&db, &dup).map(|_| "accepted".to_string())}),
    );
    // 4. verify failure texts on tampered copies of the 4-record ledger written by A
    let mut ver = serde_json::Map::new();
    for (name, file, edit) in [
        ("flip_record_byte", "records.log", 40usize),
        ("flip_checkpoint_byte", "checkpoints.log", 40usize),
    ] {
        let c = t.path().join(format!("t-{name}"));
        copy(&a, &c);
        let p = c.join("ledger").join(file);
        let mut bytes = std::fs::read(&p).unwrap();
        bytes[edit] = if bytes[edit] == b'0' { b'1' } else { b'0' };
        std::fs::write(&p, bytes).unwrap();
        ver.insert(name.into(), json!({"a": a_ver(&c), "b": b_ver(&c)}));
    }
    let c = t.path().join("t-drop-last-checkpoint");
    copy(&a, &c);
    let p = c.join("ledger/checkpoints.log");
    let text = std::fs::read_to_string(&p).unwrap();
    let kept: Vec<&str> = text.lines().take(3).collect();
    std::fs::write(&p, format!("{}\n", kept.join("\n"))).unwrap();
    ver.insert(
        "drop_last_checkpoint".into(),
        json!({"a": a_ver(&c), "b": b_ver(&c)}),
    );
    out.insert("verify_failures".into(), Value::Object(ver));
    Value::Object(out)
}

#[test]
fn p1_the_two_writers_are_deterministic_and_the_observed_behaviour_equals_the_golden() {
    let first = observe();
    let second = observe();
    assert_eq!(
        first, second,
        "the observations must not depend on time or randomness"
    );
    if std::env::var_os("PIN_WRITE").is_some() {
        std::fs::write(GOLDEN, serde_json::to_string_pretty(&first).unwrap() + "\n").unwrap();
        return;
    }
    let golden: Value = serde_json::from_str(&std::fs::read_to_string(GOLDEN).unwrap()).unwrap();
    assert_eq!(first, golden);
}

#[test]
fn p2_the_two_writers_write_identical_bytes_for_the_same_requests_and_key() {
    let o = observe();
    assert_eq!(
        o["files_a"], o["files_b"],
        "A and B must write the same ledger bytes"
    );
    assert_eq!(o["receipts_a"], o["receipts_b"]);
}

#[test]
fn p3_a_refused_request_leaves_the_ledger_empty_in_both_writers() {
    let o = observe();
    let empty = json!({"checkpoints.log": sha(Path::new("/nonexistent")), "records.log": sha(Path::new("/nonexistent"))});
    assert_eq!(o["empty_after_errors_a"], empty);
    assert_eq!(o["empty_after_errors_b"], empty);
}
