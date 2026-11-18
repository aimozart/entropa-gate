//! R1 task 1: the `entropa-standards` command line (seal, versions, inspect) on the synthetic fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::{Command, Output};

fn fx(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_entropa-standards"))
        .args(args)
        .output()
        .unwrap()
}
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}
fn setup(t: &Path) -> (String, String, String) {
    let src = t.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::copy(fx("oscal_mini.json"), src.join("oscal_mini.json")).unwrap();
    std::fs::copy(fx("pci_mini.txt"), src.join("pci_mini.txt")).unwrap();
    let sha = |n: &str| hex::encode(Sha256::digest(std::fs::read(src.join(n)).unwrap()));
    let spec = t.join("spec.json");
    std::fs::write(
        &spec,
        format!(
            r#"{{"corpus_version":"cli-1","sources":[{{"standard":"SYN-OSCAL","std_version":"1","tier":"OPEN","format":"oscal","file":"oscal_mini.json","sha256":"{}"}},{{"standard":"SYN-PAY","std_version":"1","tier":"LICENSED","format":"pci_text","file":"pci_mini.txt","sha256":"{}"}}]}}"#,
            sha("oscal_mini.json"), sha("pci_mini.txt")
        ),
    )
    .unwrap();
    (
        spec.to_str().unwrap().into(),
        src.to_str().unwrap().into(),
        t.join("store").to_str().unwrap().into(),
    )
}

#[test]
fn c1_seal_then_versions_then_inspect() {
    let t = tempfile::tempdir().unwrap();
    let (spec, src, store) = setup(t.path());
    let o = run(&[
        "seal",
        "--spec",
        &spec,
        "--sources",
        &src,
        "--store",
        &store,
    ]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        out(&o).contains("sealed cli-1")
            && out(&o).contains("6 clauses")
            && out(&o).contains("2 sources"),
        "{}",
        out(&o)
    );
    assert_eq!(out(&run(&["versions", "--store", &store])).trim(), "cli-1");
    let i = out(&run(&["inspect", "--store", &store, "--version", "cli-1"]));
    assert!(
        i.contains("SYN-OSCAL")
            && i.contains("OPEN")
            && i.contains("SYN-PAY")
            && i.contains("LICENSED")
            && i.contains("corpus_hash"),
        "{i}"
    );
    assert!(
        !i.contains("without alerts"),
        "inspect prints counts and hashes, never clause text"
    );
}

#[test]
fn c2_sealing_the_same_content_again_says_so_and_exits_zero() {
    let t = tempfile::tempdir().unwrap();
    let (spec, src, store) = setup(t.path());
    assert!(run(&[
        "seal",
        "--spec",
        &spec,
        "--sources",
        &src,
        "--store",
        &store
    ])
    .status
    .success());
    let o = run(&[
        "seal",
        "--spec",
        &spec,
        "--sources",
        &src,
        "--store",
        &store,
    ]);
    assert!(o.status.success());
    assert!(out(&o).contains("already sealed"), "{}", out(&o));
}

#[test]
fn c3_a_changed_source_is_refused_with_exit_3_and_nothing_is_overwritten() {
    let t = tempfile::tempdir().unwrap();
    let (spec, src, store) = setup(t.path());
    assert!(run(&[
        "seal",
        "--spec",
        &spec,
        "--sources",
        &src,
        "--store",
        &store
    ])
    .status
    .success());
    let before = std::fs::read(Path::new(&store).join("cli-1/clauses.jsonl")).unwrap();
    std::fs::write(
        Path::new(&src).join("pci_mini.txt"),
        "12.9.9 Changed text.\n",
    )
    .unwrap();
    let o = run(&[
        "seal",
        "--spec",
        &spec,
        "--sources",
        &src,
        "--store",
        &store,
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", err(&o));
    assert!(err(&o).contains("refused"));
    assert_eq!(
        std::fs::read(Path::new(&store).join("cli-1/clauses.jsonl")).unwrap(),
        before
    );
}

#[test]
fn c4_bad_usage_exits_2_and_never_writes() {
    let t = tempfile::tempdir().unwrap();
    let (spec, src, store) = setup(t.path());
    for args in [
        vec![],
        vec!["seal"],
        vec!["seal", "--spec", &spec],
        vec!["nonsense"],
        vec!["inspect", "--store", &store],
        vec!["versions"],
    ] {
        let o = run(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", err(&o));
    }
    let o = run(&[
        "seal",
        "--spec",
        "/nonexistent/spec.json",
        "--sources",
        &src,
        "--store",
        &store,
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(!Path::new(&store).exists());
}

#[test]
fn c5_a_missing_pdf_extractor_or_pdf_is_a_clean_error() {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("x.pdf"), b"%PDF-1.4 not really").unwrap();
    let sha = hex::encode(Sha256::digest(b"%PDF-1.4 not really"));
    let spec = t.path().join("s.json");
    std::fs::write(&spec, format!(r#"{{"corpus_version":"p1","sources":[{{"standard":"X","std_version":"1","tier":"OPEN","format":"eu_text","file":"x.pdf","sha256":"{sha}"}}]}}"#)).unwrap();
    let o = run(&[
        "seal",
        "--spec",
        spec.to_str().unwrap(),
        "--sources",
        src.to_str().unwrap(),
        "--store",
        t.path().join("st").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(4), "{}", err(&o));
    assert!(err(&o).contains("cannot extract"), "{}", err(&o));
}

fn eval_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("eval")
}

#[test]
fn c6_eval_needs_its_arguments_and_a_sealed_store() {
    let t = tempfile::tempdir().unwrap();
    let ed = eval_dir();
    let e = ed.to_str().unwrap();
    for args in [
        vec!["eval"],
        vec!["eval", "--store", "x"],
        vec!["eval", "--store", "x", "--version", "v", "--eval-dir", e],
    ] {
        assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
    }
    let o = run(&[
        "eval",
        "--store",
        t.path().to_str().unwrap(),
        "--version",
        "nope",
        "--eval-dir",
        e,
        "--out",
        t.path().join("out").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(4), "{}", err(&o));
    assert!(
        !t.path().join("out").exists(),
        "nothing is written when the corpus cannot be opened"
    );
}

#[test]
fn c7_eval_refuses_a_changed_frozen_set_and_never_overwrites_results() {
    let t = tempfile::tempdir().unwrap();
    let (spec, src, store) = setup(t.path());
    assert!(run(&[
        "seal",
        "--spec",
        &spec,
        "--sources",
        &src,
        "--store",
        &store
    ])
    .status
    .success());
    let copy = t.path().join("eval");
    for d in ["sets", "fixtures"] {
        std::fs::create_dir_all(copy.join(d)).unwrap();
        for e in std::fs::read_dir(eval_dir().join(d)).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), copy.join(d).join(e.file_name())).unwrap();
        }
    }
    std::fs::copy(eval_dir().join("FROZEN.json"), copy.join("FROZEN.json")).unwrap();
    let q = copy.join("sets/out_of_corpus.jsonl");
    std::fs::write(
        &q,
        std::fs::read_to_string(&q)
            .unwrap()
            .replacen("SOC 2", "SOC 9", 1),
    )
    .unwrap();
    let out = t.path().join("out");
    let o = run(&[
        "eval",
        "--store",
        &store,
        "--version",
        "cli-1",
        "--eval-dir",
        copy.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", err(&o));
    assert!(err(&o).contains("changed after the freeze"));
    assert!(!out.exists());
}

#[test]
fn c8_cites_check_passes_on_the_committed_manifest_and_exits_3_on_drift() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cites = repo.join("compliance/citations.json");
    let manifest = repo.join("docs/evidence/r1/manifest-c2026-11-13.json");
    let o = run(&[
        "cites-check",
        "--citations",
        cites.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--repo",
        repo.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}{}", out(&o), err(&o));
    assert!(
        out(&o).contains("no drift")
            && out(&o).contains("17 register rows")
            && out(&o).contains("3 guardrails"),
        "{}",
        out(&o)
    );
    let t = tempfile::tempdir().unwrap();
    let mut m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();
    for c in m["clauses"].as_array_mut().unwrap() {
        if c["standard"] == "NIST-SP-800-53" && c["id"] == "SI-10" {
            c["text_sha256"] = serde_json::Value::String("0".repeat(64));
        }
    }
    let changed = t.path().join("m.json");
    std::fs::write(&changed, m.to_string()).unwrap();
    let o = run(&[
        "cites-check",
        "--citations",
        cites.to_str().unwrap(),
        "--manifest",
        changed.to_str().unwrap(),
        "--repo",
        repo.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(3), "{}{}", out(&o), err(&o));
    assert!(
        err(&o).contains("drift") && err(&o).contains("SI-10"),
        "{}",
        err(&o)
    );
    assert_eq!(run(&["cites-check"]).status.code(), Some(2));
}
