//! NODECORE step 2 (RED): the contract of `entropa-nodecore`, with expected values taken from the UNMOVED code (platinum, copy A, and the golden `crates/gate/tests/pins/nodecore.json` produced by step 1),
//! never from the new crate. Decision D1 (the reviewer, 2026-11-16): duplicate keys are refused everywhere, so the one expected difference from A is the text and the verdict for a duplicated key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::{CheckpointSigner, Probe, SignError};
use entropa_ledger::Kind;
use entropa_nodecore::{
    append, council_event, decision_fields, evidence_event, verify_ledger, NodeError,
};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../gate/tests/pins/nodecore.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn probe() -> Probe {
    Probe::from_signing_key_hex(&format!("{:02x}", 7u8).repeat(32)).unwrap()
}
fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nodecore-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn fnv(p: &Path) -> String {
    let b = std::fs::read(p).unwrap_or_default();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in &b {
        h = (h ^ u64::from(*x)).wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}:{}", b.len())
}
fn req(n: u32) -> String {
    format!(
        r#"{{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"synthetic question {n}","output":"SELECT {n}","run_id":"run-pin-{n}","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":{n},"output_tokens":4,"cost_micro_usd":9,"ts":{}}}"#,
        1_700_000_000 + n
    )
}
const EVID: &str = r#"{"kind":"evidence.policy","label":"policy_verdict","decision":"allow","reason":"within_limits","control":"hitrust_01_access_control","total":1,"passed":1,"flagged":0,"detail":"detail-1","run_id":"0000000000000000000000000000000000000000000000000000000000000001","ts":1800000001}"#;
const COUNCIL: &str = r#"{"label":"council_session","actor":"scheduler-agent","decision":"info","reason":"none","subject":"synthetic subject","session_id":"session-1","ts":1800000002}"#;

fn write_decision(d: &Path, n: u32) -> Result<(), NodeError> {
    let p = probe();
    let f = decision_fields(&req(n), &p.pubkey_hex())?;
    append(d, "ledger", &p, &f).map(|_| ())
}

#[test]
fn n1_four_decision_appends_write_the_golden_bytes_and_receipts() {
    let d = dir("n1");
    for n in 1..=4 {
        write_decision(&d, n).unwrap();
    }
    let g = golden();
    for f in ["records.log", "checkpoints.log"] {
        assert_eq!(
            Value::String(fnv(&d.join("ledger").join(f))),
            g["files_a"][f],
            "{f}"
        );
    }
    let pk = probe().pubkey_hex();
    assert_eq!(
        verify_ledger(&d, "ledger", |k| k == Kind::PlatinumDecision, &pk).unwrap(),
        "OK records=4 checkpoints=4"
    );
}

#[test]
fn n2_evidence_and_council_events_equal_the_platinum_bytes() {
    let (a, c) = (dir("n2a"), dir("n2c"));
    let p = probe();
    entropa_platinum::log_evidence_with(&a, &p, EVID).unwrap();
    entropa_platinum::log_council_with(&a, &p, COUNCIL).unwrap();
    let pk = p.pubkey_hex();
    append(
        &c,
        "evidence-ledger",
        &p,
        &evidence_event(EVID, &pk).unwrap(),
    )
    .unwrap();
    append(
        &c,
        "council-ledger",
        &p,
        &council_event(COUNCIL, &pk).unwrap(),
    )
    .unwrap();
    for (sub, f) in [
        ("evidence-ledger", "records.log"),
        ("evidence-ledger", "checkpoints.log"),
        ("council-ledger", "records.log"),
        ("council-ledger", "checkpoints.log"),
    ] {
        assert_ne!(
            fnv(&a.join(sub).join(f)),
            fnv(Path::new("/nonexistent")),
            "{sub}/{f} empty: proves nothing"
        );
        assert_eq!(
            fnv(&a.join(sub).join(f)),
            fnv(&c.join(sub).join(f)),
            "{sub}/{f}"
        );
    }
}

#[test]
fn n3_every_refusal_text_equals_the_unmoved_platinum_text_except_the_duplicate_key_decision() {
    let g = golden();
    let pk = probe().pubkey_hex();
    let good = req(9);
    let cases: Vec<(&str, String)> = vec![
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
    for (name, body) in cases {
        let e = decision_fields(&body, &pk).unwrap_err();
        assert!(matches!(e, NodeError::Invalid(_)), "{name}: {e:?}");
        assert_eq!(
            Value::String(e.to_string()),
            g["errors"][name]["a"],
            "{name}"
        );
    }
    // not JSON: D1 changes the text of platinum to the gate's wording (it also names a duplicated key)
    let e = decision_fields("not json", &pk).unwrap_err();
    assert_eq!(
        e,
        NodeError::Invalid("request is not JSON (or has a duplicated key)".into())
    );
}

#[test]
fn n4_a_duplicated_key_is_refused_in_all_three_schemas() {
    let pk = probe().pubkey_hex();
    let dup_d = req(9).replacen("\"run_id\"", "\"label\":\"nl_query\",\"run_id\"", 1);
    let dup_e = EVID.replacen("\"run_id\"", "\"label\":\"policy_verdict\",\"run_id\"", 1);
    let dup_c = COUNCIL.replacen(
        "\"session_id\"",
        "\"label\":\"council_session\",\"session_id\"",
        1,
    );
    let want = NodeError::Invalid("request is not JSON (or has a duplicated key)".into());
    assert_eq!(decision_fields(&dup_d, &pk).unwrap_err(), want);
    assert_eq!(evidence_event(&dup_e, &pk).unwrap_err(), want);
    assert_eq!(council_event(&dup_c, &pk).unwrap_err(), want);
    // and the same request without the duplicate is fine (the refusal is about the duplicate, not the content)
    assert!(decision_fields(&req(9), &pk).is_ok());
    assert!(evidence_event(EVID, &pk).is_ok());
    assert!(council_event(COUNCIL, &pk).is_ok());
}

#[test]
fn n5_verify_failures_have_the_unmoved_platinum_texts() {
    let g = golden();
    let d = dir("n5");
    for n in 1..=4 {
        write_decision(&d, n).unwrap();
    }
    let pk = probe().pubkey_hex();
    for (name, file, flip) in [
        ("flip_record_byte", "records.log", true),
        ("flip_checkpoint_byte", "checkpoints.log", true),
        ("drop_last_checkpoint", "checkpoints.log", false),
    ] {
        let c = dir(&format!("n5-{name}"));
        std::fs::create_dir_all(c.join("ledger")).unwrap();
        for f in ["records.log", "checkpoints.log"] {
            std::fs::copy(d.join("ledger").join(f), c.join("ledger").join(f)).unwrap();
        }
        let p = c.join("ledger").join(file);
        if flip {
            let mut b = std::fs::read(&p).unwrap();
            b[40] = if b[40] == b'0' { b'1' } else { b'0' };
            std::fs::write(&p, b).unwrap();
        } else {
            let t = std::fs::read_to_string(&p).unwrap();
            let kept: Vec<&str> = t.lines().take(3).collect();
            std::fs::write(&p, format!("{}\n", kept.join("\n"))).unwrap();
        }
        let e = verify_ledger(&c, "ledger", |k| k == Kind::PlatinumDecision, &pk).unwrap_err();
        assert_eq!(
            Value::String(e.to_string()),
            g["verify_failures"][name]["a"]["Err"],
            "{name}"
        );
    }
    // a wrong key verifies nothing
    let other = Probe::from_signing_key_hex(&format!("{:02x}", 8u8).repeat(32)).unwrap();
    assert!(verify_ledger(
        &d,
        "ledger",
        |k| k == Kind::PlatinumDecision,
        &other.pubkey_hex()
    )
    .is_err());
    // the accepted kinds are a parameter: the same ledger is refused when the kind is not accepted
    assert!(verify_ledger(&d, "ledger", |_| false, &pk).is_err());
}

struct Failing(Probe);
impl CheckpointSigner for Failing {
    fn algorithm(&self) -> &'static str {
        self.0.algorithm()
    }
    fn pubkey_hex(&self) -> String {
        self.0.pubkey_hex()
    }
    fn try_sign_hex(&self, _msg: &[u8]) -> Result<String, SignError> {
        Err(SignError::Backend("synthetic failure".into()))
    }
}

#[test]
fn n6_a_failing_signer_leaves_the_ledger_exactly_as_it_was() {
    let d = dir("n6");
    write_decision(&d, 1).unwrap();
    let before = (
        fnv(&d.join("ledger/records.log")),
        fnv(&d.join("ledger/checkpoints.log")),
    );
    assert_ne!(before.0, fnv(Path::new("/nonexistent")));
    let f = decision_fields(&req(2), &probe().pubkey_hex()).unwrap();
    let e = append(&d, "ledger", &Failing(probe()), &f).unwrap_err();
    assert!(matches!(e, NodeError::Io(_)), "{e:?}");
    assert_eq!(
        before,
        (
            fnv(&d.join("ledger/records.log")),
            fnv(&d.join("ledger/checkpoints.log"))
        )
    );
}

#[test]
fn n7_the_dependency_tree_holds_no_network_or_cloud_crate() {
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "tree",
            "--offline",
            "-p",
            "entropa-nodecore",
            "-e",
            "normal",
            "--prefix",
            "none",
        ])
        .output()
        .unwrap();
    let t = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        t.contains("entropa-core"),
        "the tree is empty: the check proves nothing"
    );
    for bad in [
        "reqwest",
        "hyper",
        "axum",
        "tokio",
        "entropa-kms",
        "rustls",
        "openssl",
    ] {
        assert!(
            !t.lines().any(|l| l.starts_with(bad)),
            "{bad} is in the tree"
        );
    }
}

// ---- mutation triage (first run: 35 mutants, 5 missed) ----
#[test]
fn q1_a_request_without_ts_gets_the_current_time_and_one_with_ts_keeps_it() {
    let pk = probe().pubkey_hex();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let no_ts = req(5).replace(&format!(",\"ts\":{}", 1_700_000_005u64), "");
    assert!(
        !no_ts.contains("\"ts\""),
        "the replacement did not remove ts: the test proves nothing"
    );
    let f = decision_fields(&no_ts, &pk).unwrap();
    assert!(
        f.ts >= before && f.ts <= before + 60,
        "ts {} not near {before}",
        f.ts
    );
    assert_eq!(decision_fields(&req(5), &pk).unwrap().ts, 1_700_000_005);
}

#[test]
fn q2_council_model_fields_all_five_or_none() {
    let pk = probe().pubkey_hex();
    let five = COUNCIL.replace(
        "\"ts\"",
        "\"provider\":\"vertex\",\"model_id\":\"gemini-3.8-flash\",\"input_tokens\":1,\"output_tokens\":2,\"cost_micro_usd\":3,\"ts\"",
    );
    let with = council_event(&five, &pk).unwrap();
    let without = council_event(COUNCIL, &pk).unwrap();
    assert_ne!(with.subject_hash, "", "the event exists");
    assert_ne!(
        format!("{with:?}"),
        format!("{without:?}"),
        "the model fields must reach the event"
    );
    let three = COUNCIL.replace(
        "\"ts\"",
        "\"provider\":\"vertex\",\"model_id\":\"m\",\"input_tokens\":1,\"ts\"",
    );
    assert_eq!(
        council_event(&three, &pk).unwrap_err(),
        NodeError::Invalid(
            "model fields come together: provider, model_id, tokens and cost".into()
        )
    );
}
