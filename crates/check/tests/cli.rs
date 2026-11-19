//! The command line, process level. The wrappers run against stub tools in a private PATH (nothing real is run, nothing is downloaded). Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_entropa-check")
}
fn sample(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("sample")
        .join(file)
}
fn run(args: &[&str]) -> Output {
    Command::new(exe()).args(args).output().unwrap()
}
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}
fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

#[test]
fn c1_bounds_prints_the_two_bounds_and_refuses_impossible_counts() {
    let o = run(&["bounds", "--n", "100", "--k", "0"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(
        out(&o).contains("upper95: 0.029513") && out(&o).contains("lower95: 0.000000"),
        "{}",
        out(&o)
    );
    let o = run(&["bounds", "--n", "100", "--k", "1"]);
    assert!(out(&o).contains("upper95: 0.043587"), "{}", out(&o));
    for bad in [
        vec!["bounds", "--n", "0", "--k", "0"],
        vec!["bounds", "--n", "5", "--k", "6"],
        vec!["bounds", "--n", "x", "--k", "1"],
        vec!["bounds"],
    ] {
        assert_eq!(code(&run(&bad)), 2, "{bad:?}");
    }
}

#[test]
fn c2_usage_and_unknown_commands_exit_2_and_say_nothing_about_content() {
    for a in [
        vec![],
        vec!["nonsense"],
        vec!["sealed"],
        vec!["prereg"],
        vec!["prereg", "nonsense"],
    ] {
        let o = run(&a);
        assert_eq!(code(&o), 2, "{a:?}");
        assert!(err(&o).contains("usage"), "{a:?}: {}", err(&o));
    }
}

fn set_args(d: &Path, guard: &str, out_name: &str) -> Vec<String> {
    let set = sample("sample-set.json");
    vec![
        "sealed".into(),
        "--file".into(),
        set.display().to_string(),
        "--sha".into(),
        sha(&std::fs::read(&set).unwrap()),
        "--out".into(),
        d.join(out_name).display().to_string(),
        "--target".into(),
        sample(guard).display().to_string(),
        "--forecast".into(),
        sample("sample-forecast.json").display().to_string(),
    ]
}

#[test]
fn c3_sealed_runs_once_prints_a_summary_without_content_and_refuses_a_second_run() {
    let d = scratch("c3");
    let mut a = set_args(&d, "guard-flawed.sh", "r.json");
    a.push("--no-prereg".into());
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    let o = run(&refs);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(
        out(&o).contains("failed: 8 of 40") && out(&o).contains("unregistered"),
        "{}",
        out(&o)
    );
    assert!(!out(&o).contains("SYNKEY") && !err(&o).contains("SYNKEY"));
    let report = std::fs::read_to_string(d.join("r.json")).unwrap();
    assert!(report.contains("entropa-report-v1"));
    let o2 = run(&refs);
    assert_eq!(code(&o2), 2, "a second run is refused");
    assert_eq!(std::fs::read_to_string(d.join("r.json")).unwrap(), report);
    // no --no-prereg and no prereg: refused
    let b = set_args(&d, "guard-fixed.sh", "r2.json");
    let refs: Vec<&str> = b.iter().map(String::as_str).collect();
    let o = run(&refs);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("pre-registration"), "{}", err(&o));
    assert!(!d.join("r2.json").exists());
}

fn key(d: &Path, byte: &str) -> (PathBuf, String) {
    let f = write(d, &format!("key-{byte}"), &format!("{}\n", byte.repeat(32)));
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    (
        f,
        entropa_core::Probe::from_signing_key_hex(&byte.repeat(32))
            .unwrap()
            .pubkey_hex(),
    )
}

#[test]
fn c4_prereg_make_verify_and_a_registered_run() {
    let d = scratch("c4");
    let (kf, pk) = key(&d, "7a");
    let set = sample("sample-set.json");
    let prereg = d.join("prereg.json");
    let make = |extra: &[&str]| {
        let mut a: Vec<String> = [
            "prereg",
            "make",
            "--stage",
            "sample",
            "--file",
            set.to_str().unwrap(),
            "--forecast",
            sample("sample-forecast.json").to_str().unwrap(),
            "--target",
            sample("guard-fixed.sh").to_str().unwrap(),
            "--key",
            kf.to_str().unwrap(),
            "--out",
            prereg.to_str().unwrap(),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        a.extend(extra.iter().map(|s| s.to_string()));
        let r: Vec<&str> = a.iter().map(String::as_str).collect();
        run(&r)
    };
    // a key equal to a release key is refused, and nothing is written
    let id = entropa_release::cli::key_id(&pk);
    let o = make(&["--not-key-id", &id]);
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(!prereg.exists());
    let o = make(&["--not-key-id", "0000000000000000"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(
        out(&o).contains("public key: ") && !out(&o).contains(&"7a".repeat(32)),
        "the public key is printed, the seed never"
    );
    // verify
    let o = run(&[
        "prereg",
        "verify",
        "--prereg",
        prereg.to_str().unwrap(),
        "--pubkey",
        &pk,
    ]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(
        out(&o).contains("stage: sample") && out(&o).contains("set_sha256: "),
        "{}",
        out(&o)
    );
    assert_eq!(
        code(&run(&[
            "prereg",
            "verify",
            "--prereg",
            prereg.to_str().unwrap(),
            "--pubkey",
            &"00".repeat(1952)
        ])),
        2
    );
    // a registered run: same binary hashed at make time and at run time
    let mut a = set_args(&d, "guard-fixed.sh", "r.json");
    a.extend([
        "--prereg".into(),
        prereg.display().to_string(),
        "--prereg-pubkey".into(),
        pk.clone(),
    ]);
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    let o = run(&refs);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(
        out(&o).contains("pre-registration: matched") && out(&o).contains("anchored: no"),
        "{}",
        out(&o)
    );
    // the key file must be private
    std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::rename(&prereg, d.join("old.json")).unwrap();
    assert_eq!(code(&make(&[])), 2);
}

fn stubs(d: &Path, tools: &[(&str, &str)]) -> PathBuf {
    let bin = d.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for (n, body) in tools {
        script(&bin, n, body);
    }
    bin
}
fn run_with_path(bin: &Path, args: &[&str]) -> Output {
    Command::new(exe())
        .args(args)
        .env("PATH", bin)
        .output()
        .unwrap()
}
const LOGGER: &str = r#"echo "$0 $*" >> "$STUBLOG""#;

#[test]
fn c5_mutate_wraps_cargo_mutants_with_the_cap_and_never_downloads() {
    let d = scratch("c5");
    let log = d.join("log.txt");
    let bin = {
        let b = d.join("ok");
        std::fs::create_dir_all(&b).unwrap();
        stubs(
            &b,
            &[
                ("cargo", LOGGER),
                ("cargo-mutants", "exit 0"),
                ("systemd-run", &format!("{LOGGER}; shift 7; \"$@\"")),
                ("df", "echo Avail; echo 400G"),
            ],
        )
    };
    let o = Command::new(exe())
        .args(["mutate", "--", "--jobs", "1"])
        .env("PATH", &bin)
        .env("STUBLOG", &log)
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", err(&o));
    let l = std::fs::read_to_string(&log).unwrap();
    assert!(
        l.contains("MemoryMax=6G") && l.contains("MemorySwapMax=0"),
        "the memory cap is applied: {l}"
    );
    assert!(
        l.contains("cargo mutants --jobs 1"),
        "the arguments are passed through: {l}"
    );
    // low disk: refused, nothing run
    let low = {
        let b = d.join("low");
        std::fs::create_dir_all(&b).unwrap();
        stubs(
            &b,
            &[
                ("cargo", LOGGER),
                ("cargo-mutants", "exit 0"),
                ("systemd-run", LOGGER),
                ("df", "echo Avail; echo 10G"),
            ],
        )
    };
    let before = std::fs::read_to_string(&log).unwrap();
    let o = Command::new(exe())
        .args(["mutate", "--", "--jobs", "1"])
        .env("PATH", &low)
        .env("STUBLOG", &log)
        .output()
        .unwrap();
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("25 GB"), "{}", err(&o));
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        before,
        "nothing ran"
    );
    // the tool is missing: refused with the no-download sentence
    let none = {
        let b = d.join("none");
        std::fs::create_dir_all(&b).unwrap();
        stubs(&b, &[("cargo", LOGGER), ("df", "echo Avail; echo 400G")])
    };
    let o = run_with_path(&none, &["mutate", "--", "--jobs", "1"]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("does not download"), "{}", err(&o));
    // a tool file that is not executable is not found; a directory of that name is not a tool; a failing child gives exit 1
    let notexec = {
        let b = d.join("notexec");
        std::fs::create_dir_all(&b).unwrap();
        let st = stubs(&b, &[("cargo", LOGGER), ("df", "echo Avail; echo 400G")]);
        let f = st.join("cargo-mutants");
        std::fs::write(&f, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        st
    };
    let o = run_with_path(&notexec, &["mutate", "--", "--jobs", "1"]);
    assert_eq!(
        code(&o),
        2,
        "a non-executable cargo-mutants is not a tool: {}",
        err(&o)
    );
    let asdir = {
        let b = d.join("asdir");
        std::fs::create_dir_all(b.join("bin").join("cargo-mutants")).unwrap();
        stubs(
            &b.join("bin"),
            &[("cargo", LOGGER), ("df", "echo Avail; echo 400G")],
        )
    };
    assert_eq!(
        code(&run_with_path(&asdir, &["mutate", "--", "--jobs", "1"])),
        2,
        "a directory is not a tool"
    );
    let failing = {
        let b = d.join("failing");
        std::fs::create_dir_all(&b).unwrap();
        stubs(
            &b,
            &[
                ("cargo", "exit 3"),
                ("cargo-mutants", "exit 0"),
                ("df", "echo Avail; echo 400G"),
            ],
        )
    };
    let o = run_with_path(&failing, &["mutate", "--", "-j1"]);
    assert_eq!(
        code(&o),
        1,
        "a child that fails makes the wrapper exit 1: {}",
        err(&o)
    );
    // no systemd-run: it still runs, and says there is no memory cap
    let nosys = {
        let b = d.join("nosys");
        std::fs::create_dir_all(&b).unwrap();
        stubs(
            &b,
            &[
                ("cargo", LOGGER),
                ("cargo-mutants", "exit 0"),
                ("df", "echo Avail; echo 400G"),
            ],
        )
    };
    let o = Command::new(exe())
        .args(["mutate", "--", "-j1"])
        .env("PATH", &nosys)
        .env("STUBLOG", &log)
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(err(&o).contains("no memory cap"), "{}", err(&o));
}

#[test]
fn c6_fuzz_validates_its_arguments_and_wraps_cargo_fuzz() {
    let d = scratch("c6");
    let log = d.join("log.txt");
    let bin = stubs(
        &d,
        &[
            ("cargo", LOGGER),
            ("cargo-fuzz", "exit 0"),
            ("systemd-run", &format!("{LOGGER}; shift 7; \"$@\"")),
            ("df", "echo Avail; echo 400G"),
        ],
    );
    let o = Command::new(exe())
        .args(["fuzz", "parse_input", "30"])
        .env("PATH", &bin)
        .env("STUBLOG", &log)
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(std::fs::read_to_string(&log)
        .unwrap()
        .contains("cargo fuzz run parse_input -- -max_total_time=30"));
    for bad in [
        vec!["fuzz", "parse_input", "0"],
        vec!["fuzz", "parse_input", "86401"],
        vec!["fuzz", "parse_input", "abc"],
        vec!["fuzz", "bad name", "5"],
        vec!["fuzz", "parse_input"],
        vec!["fuzz"],
    ] {
        let o = Command::new(exe())
            .args(&bad)
            .env("PATH", &bin)
            .env("STUBLOG", &log)
            .output()
            .unwrap();
        assert_eq!(code(&o), 2, "{bad:?}");
    }
    let none = stubs(
        &d.join("none"),
        &[("cargo", LOGGER), ("df", "echo Avail; echo 400G")],
    );
    let o = run_with_path(&none, &["fuzz", "parse_input", "30"]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("does not download"), "{}", err(&o));
}

#[test]
fn c7_anchoring_end_to_end_make_records_and_sealed_reports_anchored_only_for_a_ledger_that_holds_it(
) {
    let d = scratch("c7");
    let (kf, pk) = key(&d, "7a");
    let set = sample("sample-set.json");
    let prereg = d.join("prereg.json");
    // an initialised node directory (the ledger's own key)
    let node = d.join("node");
    std::fs::create_dir_all(&node).unwrap();
    let nk = write(&node, "platinum.key", &format!("{}\n", "5c".repeat(32)));
    std::fs::set_permissions(&nk, std::fs::Permissions::from_mode(0o600)).unwrap();
    let make = |anchor: Option<&Path>, out_name: &str| {
        let outp = d.join(out_name);
        let mut a: Vec<String> = [
            "prereg",
            "make",
            "--stage",
            "sample",
            "--file",
            set.to_str().unwrap(),
            "--forecast",
            sample("sample-forecast.json").to_str().unwrap(),
            "--target",
            sample("guard-fixed.sh").to_str().unwrap(),
            "--key",
            kf.to_str().unwrap(),
            "--out",
            outp.to_str().unwrap(),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if let Some(n) = anchor {
            a.extend(["--anchor-ledger".to_string(), n.display().to_string()]);
        }
        let r: Vec<&str> = a.iter().map(String::as_str).collect();
        (run(&r), outp)
    };
    // an anchor directory without a key: refused, and NO pre-registration file is written
    let empty = d.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let (o, f) = make(Some(&empty), "p0.json");
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(!f.exists(), "a failed anchor leaves no pre-registration");
    // anchored
    let (o, f) = make(Some(&node), "p1.json");
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).contains("anchored in: "), "{}", out(&o));
    assert!(node.join("evidence-ledger").is_dir());
    let _ = &prereg;
    let run_sealed = |anchor: Option<&Path>, out_name: &str| {
        let mut a = set_args(&d, "guard-fixed.sh", out_name);
        a.extend([
            "--prereg".into(),
            f.display().to_string(),
            "--prereg-pubkey".into(),
            pk.clone(),
        ]);
        if let Some(n) = anchor {
            a.extend(["--anchor-ledger".into(), n.display().to_string()]);
        }
        let r: Vec<&str> = a.iter().map(String::as_str).collect();
        run(&r)
    };
    let o = run_sealed(Some(&node), "ra.json");
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).contains("anchored: yes"), "{}", out(&o));
    let rep: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("ra.json")).unwrap()).unwrap();
    assert_eq!(rep["prereg"]["anchored"], true);
    // a ledger that does not hold it, no ledger given: not anchored; a missing directory: refused
    let o = run_sealed(Some(&empty), "rb.json");
    assert!(out(&o).contains("anchored: no"), "{}{}", out(&o), err(&o));
    let o = run_sealed(None, "rc.json");
    assert!(out(&o).contains("anchored: no"), "{}", out(&o));
    let o = run_sealed(Some(&d.join("does-not-exist")), "rd.json");
    assert_eq!(code(&o), 2);
    assert!(!d.join("rd.json").exists());
}
