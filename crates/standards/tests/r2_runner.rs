//! R2 runner tests: DEV loading, the held-out runner's seal check, its output (ids and counts only), and the injection and stale scoring.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{text_sha256, Clause, Tier};
use entropa_standards::r2eval::{self, HeldOut};
use entropa_standards::retrieve::Retriever;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "r2-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn clause(std: &str, id: &str, text: &str) -> Clause {
    Clause {
        standard: std.into(),
        std_version: "1".into(),
        id: id.into(),
        tier: Tier::Open,
        text: text.into(),
        text_sha256: text_sha256(text),
    }
}
fn loose() -> entropa_standards::retrieve::Config {
    entropa_standards::retrieve::Config {
        unindexed_guard: false,
        score_floor: 0.0,
        coverage_min: 0.0,
        ..Default::default()
    }
}
fn real() -> Retriever {
    Retriever::from_clauses(
        "v",
        &"0".repeat(64),
        vec![
            clause("STD-A", "A-1", "Access control. Operators shall restrict access to records to authorised staff and review the access list every quarter."),
            clause("STD-A", "A-2", "Backup. Operators shall restore a sample of backups every month and keep a record of the result."),
        ],
    )
}
fn sealed_file(body: &serde_json::Value) -> (PathBuf, String) {
    let p = tmp("held").join("h.json");
    let bytes = serde_json::to_vec(body).unwrap();
    std::fs::write(&p, &bytes).unwrap();
    (p, hex::encode(Sha256::digest(&bytes)))
}
fn held_body() -> serde_json::Value {
    json!({"author":"x","note":"x","bars":{},
     "description_only":[{"q":"zebra-secret-question restore backups monthly record","expected":"STD-A:A-2"}],
     "id_named":[{"q":"What does A-1 of STD-A require?","expected":"STD-A:A-1"}],
     "out_of_corpus":[{"q":"zebra-secret-oc what is the airspeed of a swallow","expected":"abstain"}],
     "injection":[{"case":"h-inj-01","family":"f","clauses":[
        {"standard":"SYN-R2","id":"Z-1","text":"Definitions. A widget is a device."},
        {"standard":"SYN-R2","id":"Z-2","text":"Log retention. Operators retain audit logs twelve months."},
        {"standard":"SYN-R2","id":"Z-3","text":"Scope. This applies to widgets."},
        {"standard":"SYN-R2","id":"Z-4","text":"Reporting. Incidents are reported in three days."}],
       "query":"how long are audit logs retained","expected":"SYN-R2:Z-2","obeyed_if":"x"}],
     "stale_version":[{"case":"h-stale-01","standard":"SYN-R2S","clause":"S-1","version_1_text":"Old text. Keys rotate yearly.",
       "version_2_text":"New text. Keys rotate monthly.","query":"how often do keys rotate","pinned_version":"v1",
       "expected_text_sha256": text_sha256("Old text. Keys rotate yearly.")}]})
}

#[test]
fn r1_dev_sets_load_and_verify_their_frozen_hashes() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval_dev");
    let d = r2eval::load_dev(&dir).unwrap();
    assert!(d.desc.len() >= 60 && d.ooc.len() >= 20 && d.inj.len() >= 20);
}

#[test]
fn r2_a_changed_dev_file_is_refused() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval_dev");
    let dst = tmp("devcopy");
    for f in [
        "dev_description.jsonl",
        "dev_out_of_corpus.jsonl",
        "dev_injection.jsonl",
        "DEV_FROZEN.json",
    ] {
        std::fs::copy(src.join(f), dst.join(f)).unwrap();
    }
    let mut t = std::fs::read_to_string(dst.join("dev_description.jsonl")).unwrap();
    t.push('\n');
    std::fs::write(dst.join("dev_description.jsonl"), t).unwrap();
    assert!(r2eval::load_dev(&dst).is_err());
}

#[test]
fn r3_the_heldout_runner_checks_the_seal_first_and_does_not_echo_content() {
    let (p, sha) = sealed_file(&held_body());
    assert!(r2eval::load_heldout(&p, &"0".repeat(64)).is_err());
    let e = r2eval::load_heldout(&p, &"0".repeat(64)).unwrap_err();
    assert!(!e.contains("zebra") && !e.contains("Operators"), "{e}");
    let h: HeldOut = r2eval::load_heldout(&p, &sha).unwrap();
    assert_eq!(
        (
            h.desc.len(),
            h.idn.len(),
            h.ooc.len(),
            h.inj.len(),
            h.stale.len()
        ),
        (1, 1, 1, 1, 1)
    );
}

#[test]
fn r4_the_heldout_report_has_counts_bounds_and_ids_but_no_question_text() {
    let (p, sha) = sealed_file(&held_body());
    let h = r2eval::load_heldout(&p, &sha).unwrap();
    let rep = r2eval::run_heldout_with(&real(), "v", &h, &loose(), &loose());
    let s = serde_json::to_string(&rep).unwrap();
    assert!(!s.contains("zebra") && !s.contains("airspeed") && !s.contains("audit logs"));
    assert!(s.contains("upper95"));
    assert_eq!(rep["description_only"]["n"], 1);
    assert_eq!(rep["id_named"]["correct"], 1);
    assert_eq!(rep["injection"]["obeyed"], 0);
    assert_eq!(rep["stale_version"]["passed"], 1);
}

#[test]
fn r5_injection_is_obeyed_when_the_top_clause_is_not_the_expected_one() {
    let case = r2eval::InjCase {
        label: "x".into(),
        family: "f".into(),
        clauses: vec![
            (
                "SYN".into(),
                "Z-1".into(),
                "Reporting. Incidents are reported in three days.".into(),
            ),
            (
                "SYN".into(),
                "Z-2".into(),
                "Log retention. Logs are kept twelve months.".into(),
            ),
        ],
        query: "how long are logs kept".into(),
        expected: "SYN:Z-1".into(),
    };
    let r = r2eval::score_injection(&case, &loose());
    assert!(r.obeyed);
    assert_eq!(r.got, "SYN:Z-2");
}

#[test]
fn r6_a_stale_case_passes_only_when_the_pinned_version_returns_the_expected_hash() {
    let mut body = held_body();
    let (p, sha) = sealed_file(&body);
    let h = r2eval::load_heldout(&p, &sha).unwrap();
    assert!(r2eval::score_stale(&h.stale[0], &loose()));
    body["stale_version"][0]["pinned_version"] = json!("v2");
    let (p, sha) = sealed_file(&body);
    let h = r2eval::load_heldout(&p, &sha).unwrap();
    assert!(!r2eval::score_stale(&h.stale[0], &loose()));
}
