//! The planting helper (feature `plant`) produces the attacked ledgers of the threat model through the real `check` command. Fixed test seeds; synthetic data only.
#![cfg(feature = "plant")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_gate::{cli, node, plant::plant};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn req(n: u32) -> String {
    format!(
        r#"{{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"synthetic question {n}","output":"SELECT {n}","run_id":"run-plant-{n}","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":{n},"output_tokens":4,"cost_micro_usd":9,"ts":{}}}"#,
        1_700_000_000 + n
    )
}
fn ledger(root: &Path, seed: u8, n: u32) -> PathBuf {
    let d = root.join(format!("l{seed}"));
    std::fs::create_dir_all(d.join("ledger")).unwrap();
    let k = d.join("platinum.key");
    std::fs::write(&k, format!("{}\n", format!("{seed:02x}").repeat(32))).unwrap();
    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    for i in 1..=n {
        node::record(&d, &req(i)).unwrap();
    }
    d
}
fn verdict(d: &Path) -> String {
    let a: Vec<String> = ["check", "--dir", d.to_str().unwrap()]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    cli::run(&a, &mut std::io::empty(), &mut out, &mut err);
    String::from_utf8_lossy(&out)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[test]
fn x1_a_planted_honest_v2_chain_verifies_and_a_regressing_one_is_clock_regression() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), 7, 5);
    let n = plant(&d, r#"{"checkpoints":[{"v":2,"size":2,"time":100},{"v":2,"size":4,"time":200},{"v":2,"size":5,"time":300}]}"#).unwrap();
    assert_eq!(n, 3);
    assert_eq!(verdict(&d), "verdict: ok_unanchored");
    plant(&d, r#"{"checkpoints":[{"v":2,"size":2,"time":100},{"v":2,"size":4,"time":300},{"v":2,"size":5,"time":200}]}"#).unwrap();
    assert_eq!(verdict(&d), "verdict: clock_regression");
}
#[test]
fn x2_other_signing_seed_skipped_counter_wrong_prev_downgrade_and_a_planted_root() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), 7, 5);
    plant(&d, r#"{"signer_seed":"0909090909090909090909090909090909090909090909090909090909090909","checkpoints":[{"v":2,"size":5,"time":100}]}"#).unwrap();
    assert_eq!(verdict(&d), "verdict: key_changed_unlogged");
    plant(
        &d,
        r#"{"checkpoints":[{"v":2,"size":2,"time":100},{"v":2,"size":5,"time":200,"counter":5}]}"#,
    )
    .unwrap();
    assert_eq!(
        verdict(&d),
        "verdict: checkpoint_mismatch",
        "a skipped counter"
    );
    plant(&d, r#"{"checkpoints":[{"v":2,"size":2,"time":100},{"v":2,"size":5,"time":200,"prev":"0909090909090909090909090909090909090909090909090909090909090909"}]}"#).unwrap();
    assert_eq!(
        verdict(&d),
        "verdict: checkpoint_mismatch",
        "a wrong previous digest"
    );
    plant(
        &d,
        r#"{"checkpoints":[{"v":2,"size":2,"time":100},{"v":1,"size":5,"time":200}]}"#,
    )
    .unwrap();
    assert_eq!(
        verdict(&d),
        "verdict: checkpoint_mismatch",
        "a v1 after a v2"
    );
    plant(
        &d,
        r#"{"checkpoints":[{"v":1,"size":2,"time":100},{"v":2,"size":5,"time":200}]}"#,
    )
    .unwrap();
    assert_eq!(verdict(&d), "verdict: ok_unanchored", "v1 then v2");
    plant(&d, r#"{"checkpoints":[{"v":2,"size":5,"time":100,"root":"0909090909090909090909090909090909090909090909090909090909090909"}]}"#).unwrap();
    assert_eq!(
        verdict(&d),
        "verdict: checkpoint_mismatch",
        "a planted wrong root, correctly signed"
    );
}
#[test]
fn x3_the_helper_refuses_a_bad_spec_and_writes_nothing() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), 7, 3);
    let before = std::fs::read(d.join("ledger/checkpoints.log")).unwrap();
    for bad in [
        "",
        "{}",
        "[]",
        r#"{"checkpoints":[{"v":3,"size":1,"time":1}]}"#,
        r#"{"checkpoints":[{"v":2,"size":99,"time":1}]}"#,
        r#"{"checkpoints":[{"v":2,"size":1}]}"#,
        r#"{"checkpoints":[{"v":2,"size":1,"time":1,"extra":1}]}"#,
        r#"{"signer_seed":"zz","checkpoints":[]}"#,
    ] {
        assert!(plant(&d, bad).is_err(), "{bad}");
    }
    assert_eq!(
        std::fs::read(d.join("ledger/checkpoints.log")).unwrap(),
        before,
        "nothing was written"
    );
}
