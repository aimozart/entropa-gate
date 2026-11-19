//! INS slice 4 red tests (round-1 finding 1): every `entropa-gate` subcommand refuses an unknown option, a repeated option that may not be repeated, an extra word, and a missing value with a usage error (exit 2) and NO verdict line.
//! A mistyped `--require-anchors` must never turn into a pass. Fixed test seed; synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_gate::{cli, node};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn ledger(root: &Path) -> PathBuf {
    let d = root.join("l");
    std::fs::create_dir_all(d.join("ledger")).unwrap();
    let k = d.join("platinum.key");
    std::fs::write(&k, format!("{}\n", "07".repeat(32))).unwrap();
    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    node::record(&d, r#"{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"q","output":"o","run_id":"r1","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":4,"cost_micro_usd":9,"ts":1700000001}"#).unwrap();
    d
}
fn run(args: &[&str]) -> (i32, String, String) {
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(&a, &mut std::io::empty(), &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).into(),
        String::from_utf8_lossy(&err).into(),
    )
}

#[test]
fn o1_check_refuses_unknown_misspelled_repeated_and_extra_words_with_exit_2_and_no_verdict() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path());
    let dir = d.to_str().unwrap();
    for args in [
        vec!["check", "--dir", dir, "--bogus"],
        vec!["check", "--dir", dir, "--require-anchors"], // the typo that used to pass
        vec![
            "check",
            "--dir",
            dir,
            "--require-anchor",
            "--require-anchor",
        ],
        vec!["check", "--dir", dir, "--dir", dir],
        vec!["check", "--dir", dir, "extra"],
        vec!["check", "extra", "--dir", dir],
        vec!["check", "--dir", dir, "--anchor"],
        vec!["check", "--dir", dir, "-x"],
        vec!["check", "--dir=".to_string().as_str(), dir],
    ] {
        let r = run(&args);
        assert_eq!(r.0, 2, "{args:?}: {r:?}");
        assert!(
            !r.1.contains("verdict"),
            "{args:?}: no verdict line: {}",
            r.1
        );
        assert!(r.2.starts_with("usage:"), "{args:?}: {}", r.2);
    }
    // the allowed forms still work, and --anchor may repeat
    assert_eq!(run(&["check", "--dir", dir]).0, 0);
    assert_eq!(
        run(&["check", "--dir", dir, "--require-anchor"]).0,
        1,
        "anchor_missing is an alarm, not a usage error"
    );
}
#[test]
fn o2_anchor_export_refuses_unknown_and_repeated_options() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path());
    let (dir, out) = (d.to_str().unwrap(), t.path().join("a.anchor"));
    let out = out.to_str().unwrap();
    for args in [
        vec!["anchor", "export", "--dir", dir, "--out", out, "--bogus"],
        vec![
            "anchor", "export", "--dir", dir, "--out", out, "--signed", "--signed",
        ],
        vec!["anchor", "export", "--dir", dir, "--out", out, "--out", out],
        vec!["anchor", "export", "--dir", dir, "--dir", dir, "--out", out],
        vec!["anchor", "export", "--dir", dir, "--out", out, "extra"],
        vec!["anchor", "export", "--dir", dir, "--out", out, "--sign"],
    ] {
        let r = run(&args);
        assert_eq!(r.0, 2, "{args:?}: {r:?}");
        assert!(r.2.starts_with("usage:"), "{args:?}: {}", r.2);
    }
    assert!(
        !Path::new(out).exists(),
        "nothing was written by a refused command"
    );
    assert_eq!(
        run(&["anchor", "export", "--dir", dir, "--out", out, "--signed"]).0,
        0
    );
}
#[test]
fn o3_the_older_subcommands_are_strict_too() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path());
    let dir = d.to_str().unwrap();
    for args in [
        vec!["verify", "--dir", dir, "--bogus"],
        vec!["verify", "--dir", dir, "--dir", dir],
        vec!["verify", "--dir", dir, "extra"],
        vec!["status", "--dir", dir, "--bogus"],
        vec!["status", "--dir", dir, "--config", "x", "--config", "y"],
        vec!["record", "--dir", dir, "--bogus"],
        vec!["init", "--dir", dir, "--bogus"],
        vec![
            "explorer", "--dir", dir, "--config", "c", "--out", "o", "--bogus",
        ],
        vec!["licence", "check", "--file", "f", "--bogus"],
        vec!["licence", "check", "--file", "f", "--file", "g"],
    ] {
        let r = run(&args);
        assert_eq!(r.0, 2, "{args:?}: {r:?}");
        assert!(r.2.contains("usage"), "{args:?}: {}", r.2);
    }
    assert_eq!(run(&["verify", "--dir", dir]).0, 0);
    assert_eq!(run(&["status", "--dir", dir]).0, 0);
}

#[test]
fn o4_the_allowed_forms_of_every_subcommand_still_work() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path());
    let dir = d.to_str().unwrap();
    let cfg = t.path().join("c.toml");
    std::fs::write(
        &cfg,
        "org_name = \"Example Org\"\nwitnesses = [\"https://witness.example.invalid/w\"]\n",
    )
    .unwrap();
    let out = t.path().join("site");
    let r = run(&[
        "explorer",
        "--dir",
        dir,
        "--config",
        cfg.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.0, 0, "{r:?}");
    assert!(out.join("index.html").exists());
    let s = run(&["status", "--dir", dir, "--config", cfg.to_str().unwrap()]);
    assert!(s.1.contains("org: Example Org"), "{s:?}");
    let init_dir = t.path().join("fresh");
    assert_eq!(run(&["init", "--dir", init_dir.to_str().unwrap()]).0, 0);
    assert_eq!(
        run(&["licence", "check", "--file", "missing-file"]).0,
        1,
        "a usage-valid licence call reaches the licence code"
    );
}
