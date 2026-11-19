//! KEYS1 (a stage record (not published)): a separate signing key per ledger. All data is synthetic; key material never appears in an output of keys-check.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("keys1-{name}-{}-{nanos}", std::process::id()))
}
fn run(args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_entropa-platinum"))
        .args(args)
        .env_remove("PLATINUM_KEY_FILE")
        .env_remove("ENTROPA_GCP_KMS_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

const DEC: &str = r#"{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"How many claims were denied by payer?","output":"SELECT payer, COUNT(*) FROM platinum.denials GROUP BY payer LIMIT 100","run_id":"run-2026-11-05-s","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":120,"output_tokens":40,"cost_micro_usd":90}"#;
const EVI: &str = r#"{"kind":"evidence.control_check","label":"rls_test","decision":"allow","reason":"check_passed","control":"hipaa_164_312_a1","total":25,"passed":25,"flagged":0,"detail":"wrong-actor queries returned zero rows","run_id":"run-rls-1"}"#;
const COU: &str = r#"{"label":"council_session","actor":"scheduler-agent","decision":"info","reason":"none","subject":"weekly session 45 opened","session_id":"council-2026-w45"}"#;

fn key_of(d: &std::path::Path, file: &str) -> String {
    std::fs::read_to_string(d.join(file))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn k1_init_creates_two_distinct_keys_with_mode_0600_and_no_council_key() {
    let d = dir("k1");
    let ds = d.to_str().unwrap();
    assert!(run(&["init", ds], None).status.success());
    for f in ["decisions.key", "evidence.key"] {
        let mode = std::fs::metadata(d.join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{f}");
        assert_eq!(key_of(&d, f).len(), 64, "{f}");
    }
    assert_ne!(key_of(&d, "decisions.key"), key_of(&d, "evidence.key"));
    assert!(
        !d.join("council.key").exists(),
        "the council key is optional"
    );
    assert!(
        !d.join("platinum.key").exists(),
        "a new node has no shared key"
    );
}

#[test]
fn k2_keys_add_creates_the_council_key_once_and_never_overwrites() {
    let d = dir("k2");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    assert!(run(&["keys-add", ds, "council"], None).status.success());
    let first = key_of(&d, "council.key");
    assert_eq!(
        std::fs::metadata(d.join("council.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let again = run(&["keys-add", ds, "council"], None);
    assert!(!again.status.success());
    assert_eq!(key_of(&d, "council.key"), first, "never overwritten");
    assert!(!run(&["keys-add", ds, "nonsense"], None).status.success());
    let evi = run(&["keys-add", ds, "evidence"], None);
    assert!(!evi.status.success(), "an existing key is refused");
}

#[test]
fn k3_each_ledger_signs_with_its_own_key_and_the_key_ids_differ() {
    let d = dir("k3");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    run(&["keys-add", ds, "council"], None);
    assert!(run(&["log", ds], Some(DEC)).status.success());
    assert!(run(&["log-evidence", ds], Some(EVI)).status.success());
    assert!(run(&["log-council", ds], Some(COU)).status.success());
    let dec: serde_json::Value =
        serde_json::from_str(&out(&run(&["export-decisions", ds], None))).unwrap();
    let evi: serde_json::Value =
        serde_json::from_str(&out(&run(&["export-evidence", ds], None))).unwrap();
    let cou: serde_json::Value =
        serde_json::from_str(&out(&run(&["export-council", ds], None))).unwrap();
    let ids = [
        dec["records"][0]["key_id"].as_str().unwrap().to_string(),
        evi["records"][0]["key_id"].as_str().unwrap().to_string(),
        cou["records"][0]["key_id"].as_str().unwrap().to_string(),
    ];
    assert!(
        ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2],
        "{ids:?}"
    );
    // the bundle of each ledger carries the public key of ITS key (K8)
    let pk = |l: &str| out(&run(&["pubkey", ds, l], None)).trim().to_string();
    assert_eq!(dec["pubkey"].as_str().unwrap(), pk("decisions"));
    assert_eq!(evi["pubkey"].as_str().unwrap(), pk("evidence"));
    assert_eq!(cou["pubkey"].as_str().unwrap(), pk("council"));
    assert!(pk("decisions") != pk("evidence"));
    for c in ["verify", "verify-evidence", "verify-council"] {
        assert!(run(&[c, ds], None).status.success(), "{c}");
    }
}

#[test]
fn k4_a_ledger_does_not_verify_under_another_ledgers_key() {
    let d = dir("k4");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    run(&["log", ds], Some(DEC));
    run(&["log-evidence", ds], Some(EVI));
    let pk = |l: &str| out(&run(&["pubkey", ds, l], None)).trim().to_string();
    assert!(entropa_platinum::verify_with(&d, &pk("decisions")).is_ok());
    assert!(
        entropa_platinum::verify_with(&d, &pk("evidence")).is_err(),
        "the AI ledger must not verify under the evidence key"
    );
    assert!(entropa_platinum::verify_evidence_with(&d, &pk("evidence")).is_ok());
    assert!(
        entropa_platinum::verify_evidence_with(&d, &pk("decisions")).is_err(),
        "the evidence ledger must not verify under the AI key"
    );
}

#[test]
fn k5_a_legacy_node_with_only_platinum_key_still_works_and_keys_check_says_so() {
    let d = dir("k5");
    std::fs::create_dir_all(&d).unwrap();
    let seed = "5a".repeat(32);
    let f = d.join("platinum.key");
    std::fs::write(&f, format!("{seed}\n")).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ds = d.to_str().unwrap();
    assert!(run(&["log", ds], Some(DEC)).status.success());
    assert!(run(&["log-evidence", ds], Some(EVI)).status.success());
    assert!(run(&["verify", ds], None).status.success());
    assert!(run(&["verify-evidence", ds], None).status.success());
    let strict = run(&["keys-check", ds], None);
    assert!(
        !strict.status.success(),
        "a shared key is a failure unless allowed"
    );
    assert!(out(&strict).contains("legacy_shared") || err(&strict).contains("legacy_shared"));
    let lenient = run(&["keys-check", ds, "--allow-legacy"], None);
    assert!(lenient.status.success(), "{}", err(&lenient));
    assert_eq!(
        out(&lenient).matches("legacy_shared").count(),
        2,
        "decisions and evidence, no council key to report: {}",
        out(&lenient)
    );
}

#[test]
fn k6_keys_check_on_a_separated_node_passes_and_prints_distinct_key_ids_and_no_key_material() {
    let d = dir("k6");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    let o = run(&["keys-check", ds], None);
    assert!(o.status.success(), "{}", err(&o));
    let t = out(&o);
    assert_eq!(t.matches("own").count(), 2, "{t}");
    for f in ["decisions.key", "evidence.key"] {
        let secret = key_of(&d, f);
        assert!(
            !t.contains(&secret) && !err(&o).contains(&secret),
            "{f}: key material in the output"
        );
    }
    let ids: Vec<&str> = t
        .lines()
        .filter_map(|l| l.split("key_id=").nth(1))
        .map(|s| s.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(ids.len(), 2, "{t}");
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn k7_a_per_ledger_key_file_readable_by_others_is_refused() {
    let d = dir("k7");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    std::fs::set_permissions(
        d.join("evidence.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let o = run(&["log-evidence", ds], Some(EVI));
    assert!(!o.status.success());
    assert!(err(&o).contains("chmod 600"), "{}", err(&o));
    assert!(
        run(&["log", ds], Some(DEC)).status.success(),
        "the AI ledger key is unaffected"
    );
}

#[test]
fn k8_a_node_with_a_shared_key_and_one_own_key_mixes_correctly() {
    // migration state: evidence.key exists, decisions still on the legacy platinum.key
    let d = dir("k8");
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("platinum.key");
    std::fs::write(&f, format!("{}\n", "3c".repeat(32))).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ds = d.to_str().unwrap();
    assert!(run(&["keys-add", ds, "evidence"], None).status.success());
    assert!(run(&["log", ds], Some(DEC)).status.success());
    assert!(run(&["log-evidence", ds], Some(EVI)).status.success());
    let pk = |l: &str| out(&run(&["pubkey", ds, l], None)).trim().to_string();
    assert_ne!(pk("decisions"), pk("evidence"));
    let t = out(&run(&["keys-check", ds, "--allow-legacy"], None));
    assert!(t.contains("legacy_shared") && t.contains("own"), "{t}");
}

#[test]
fn k9_two_ledgers_with_the_same_own_key_fail_keys_check_even_when_legacy_is_allowed() {
    let d = dir("k9");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    let same = key_of(&d, "decisions.key");
    std::fs::write(d.join("evidence.key"), format!("{same}\n")).unwrap();
    std::fs::set_permissions(
        d.join("evidence.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    for extra in [vec![], vec!["--allow-legacy"]] {
        let mut a = vec!["keys-check", ds];
        a.extend(extra);
        let o = run(&a, None);
        assert!(!o.status.success(), "{a:?}");
        assert!(
            err(&o).contains("decisions and evidence share one key"),
            "{}",
            err(&o)
        );
        assert!(
            !err(&o).contains(&same) && !out(&o).contains(&same),
            "no key material"
        );
    }
}

fn run_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_entropa-platinum"));
    c.args(args)
        .env_remove("PLATINUM_KEY_FILE")
        .env_remove("ENTROPA_GCP_KMS_KEY");
    for (k, v) in env {
        c.env(k, v);
    }
    c.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

#[test]
fn k10_a_per_ledger_environment_override_names_that_ledgers_key_only() {
    let d = dir("k10");
    let ds = d.to_str().unwrap();
    run(&["init", ds], None);
    let ext = dir("k10ext");
    std::fs::create_dir_all(&ext).unwrap();
    let f = ext.join("secret");
    std::fs::write(&f, format!("{}\n", "9d".repeat(32))).unwrap(); // an external secret: its mode is the secret store's business
    let fs = f.to_str().unwrap();
    let before = out(&run(&["pubkey", ds, "evidence"], None))
        .trim()
        .to_string();
    let e = run_env(
        &["pubkey", ds, "evidence"],
        &[("PLATINUM_KEY_FILE_EVIDENCE", fs)],
    );
    assert!(e.status.success(), "{}", err(&e));
    assert_ne!(out(&e).trim(), before, "the evidence override is used");
    let dec = run_env(
        &["pubkey", ds, "decisions"],
        &[("PLATINUM_KEY_FILE_EVIDENCE", fs)],
    );
    assert_eq!(
        out(&dec).trim(),
        out(&run(&["pubkey", ds, "decisions"], None)).trim(),
        "the decisions key is unaffected"
    );
    let c = run_env(
        &["pubkey", ds, "council"],
        &[("PLATINUM_KEY_FILE_COUNCIL", fs)],
    );
    assert!(
        c.status.success(),
        "the council override works without a council key file: {}",
        err(&c)
    );
    assert_eq!(
        out(&c).trim(),
        out(&e).trim(),
        "same secret, same public key"
    );
    let dd = run_env(
        &["pubkey", ds, "decisions"],
        &[("PLATINUM_KEY_FILE_DECISIONS", fs)],
    );
    assert_eq!(out(&dd).trim(), out(&e).trim());
}

#[test]
fn k11_init_refuses_a_directory_that_already_holds_any_key() {
    for (n, existing) in [
        ("a", "platinum.key"),
        ("b", "council.key"),
        ("c", "decisions.key"),
        ("d", "evidence.key"),
    ] {
        let d = dir(&format!("k11{n}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(existing), "00\n").unwrap();
        let o = run(&["init", d.to_str().unwrap()], None);
        assert!(!o.status.success(), "{existing}");
        assert!(
            err(&o).contains("already initialised"),
            "{existing}: {}",
            err(&o)
        );
        assert_eq!(
            std::fs::read_to_string(d.join(existing)).unwrap(),
            "00\n",
            "{existing} untouched"
        );
    }
    let d = dir("k11e");
    assert!(run(&["init", d.to_str().unwrap()], None).status.success());
    assert!(
        !run(&["init", d.to_str().unwrap()], None).status.success(),
        "a second init"
    );
}
