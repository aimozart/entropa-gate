//! EG1f freeze item 5: the sealed-set runner with `--pipeline v2`: the hash is checked before anything is parsed, a second report is refused, an unknown pipeline is an error, the default stays v1,
//! and the switch really selects the pipeline (a planted case that v1 lets through and v2 blocks). Written AFTER the runner switch (the switch was written in the GREEN 2 commit, untested then; stated).
//! Synthetic words only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;

const PLANTED: &str = "island ember 42! harbor";

fn run(args: &[&str]) -> (i32, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_egress-eval"))
        .args(args)
        .output()
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn set() -> Value {
    let case = |id: &str, class: &str, body: Value, expect: &str, canaries: &[&str]| {
        json!({"id": id, "class": class, "subclass": "plain", "tier": "T1",
            "request": {"destination": "https://api.model.example/v1/chat", "headers": {}, "body_fields": body, "attachments": []},
            "expect": expect, "canaries": canaries})
    };
    json!({"schema": "eg-sealed-v1",
        "policy": {"destinations": [{"tier": "T1", "url_prefix": "https://api.model.example/v1/"}, {"tier": "T2", "url_prefix": "https://api.model.example/v1/"}],
                   "do_not_send_terms": [], "modes": {}},
        "cases": [
            case("s-1", "secrets", json!({"msg": format!("'password' => '{PLANTED}'")}), "no_leak", &[PLANTED]),
            case("c-1", "clean", json!({"msg": "Please summarise the retention clause."}), "allow", &[]),
        ]})
}
struct Fixture {
    _d: tempfile::TempDir,
    file: String,
    out: String,
    bytes: Vec<u8>,
}
fn fixture() -> Fixture {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("set.json");
    let bytes = serde_json::to_vec(&set()).unwrap();
    std::fs::write(&f, &bytes).unwrap();
    Fixture {
        file: f.to_str().unwrap().to_string(),
        out: d.path().join("rep.json").to_str().unwrap().to_string(),
        bytes,
        _d: d,
    }
}
fn heldout(fx: &Fixture, sha_arg: &str, extra: &[&str]) -> (i32, String) {
    let mut a = vec!["heldout-eg", "--file", &fx.file, "--sha", sha_arg, "--out", &fx.out];
    a.extend_from_slice(extra);
    run(&a)
}
fn report(fx: &Fixture) -> Value {
    serde_json::from_str(&std::fs::read_to_string(&fx.out).unwrap()).unwrap()
}

#[test]
fn g1_the_hash_is_checked_before_parsing_with_pipeline_v2_too() {
    let fx = fixture();
    let (code, err) = heldout(&fx, &"0".repeat(64), &["--pipeline", "v2"]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("nothing was parsed"), "{err}");
    assert!(!std::path::Path::new(&fx.out).exists(), "no report");
    // a file that is not JSON with a wrong hash is refused before it is parsed (not an error about JSON)
    std::fs::write(&fx.file, b"not json at all").unwrap();
    let (code, err) = heldout(&fx, &"0".repeat(64), &["--pipeline", "v2"]);
    assert_eq!(code, 3, "{err}");
    assert!(!std::path::Path::new(&fx.out).exists());
}

#[test]
fn g2_v2_runs_once_and_a_second_report_is_refused() {
    let fx = fixture();
    let (code, err) = heldout(&fx, &sha(&fx.bytes), &["--pipeline", "v2"]);
    assert_eq!(code, 0, "{err}");
    let first = std::fs::read_to_string(&fx.out).unwrap();
    let (code, err) = heldout(&fx, &sha(&fx.bytes), &["--pipeline", "v2"]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("run once"), "{err}");
    assert_eq!(std::fs::read_to_string(&fx.out).unwrap(), first, "the first report is untouched");
    // the report holds no request text
    assert!(!first.contains(PLANTED));
}

#[test]
fn g3_the_switch_selects_the_pipeline_and_the_default_is_v1() {
    let (fx1, fx2, fx3) = (fixture(), fixture(), fixture());
    assert_eq!(heldout(&fx1, &sha(&fx1.bytes), &["--pipeline", "v1"]).0, 0);
    assert_eq!(heldout(&fx2, &sha(&fx2.bytes), &["--pipeline", "v2"]).0, 0);
    assert_eq!(heldout(&fx3, &sha(&fx3.bytes), &[]).0, 0);
    let leaks = |fx: &Fixture| report(fx)["classes"]["secrets"]["failed"].clone();
    assert_eq!(leaks(&fx1), 1, "v1 lets the planted PHP-array secret through");
    assert_eq!(leaks(&fx2), 0, "v2 blocks it");
    assert_eq!(leaks(&fx3), 1, "no flag means v1");
    assert_eq!(report(&fx2)["classes"]["clean"]["failed"], 0);
}

#[test]
fn g4_an_unknown_pipeline_is_an_error_and_writes_no_report() {
    let fx = fixture();
    let (code, err) = heldout(&fx, &sha(&fx.bytes), &["--pipeline", "v3"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("--pipeline must be v1 or v2"), "{err}");
    assert!(!std::path::Path::new(&fx.out).exists(), "no report");
}
