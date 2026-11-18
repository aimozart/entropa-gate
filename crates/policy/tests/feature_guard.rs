//! S4d (ADR 0019): the request-trusting engine must not be reachable from a default build.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::fs;
use std::path::Path;

const FEATURE: &str = "trust-request-fields";

fn manifest(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

#[test]
fn g1_the_feature_is_declared_and_not_a_default_feature() {
    let m = manifest("Cargo.toml");
    assert!(
        m.contains(&format!("{FEATURE} = []")),
        "feature must be declared"
    );
    let default_line = m
        .lines()
        .find(|l| l.trim_start().starts_with("default"))
        .unwrap();
    assert!(!default_line.contains(FEATURE), "{default_line}");
}

#[test]
fn g2_no_manifest_turns_the_feature_on_except_the_crates_own_dev_dependency_and_its_fuzz_crate() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut offenders = vec![];
    for entry in fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        for rel in ["Cargo.toml", "fuzz/Cargo.toml"] {
            let Ok(text) = fs::read_to_string(dir.join(rel)) else {
                continue;
            };
            let is_policy = dir.file_name().is_some_and(|n| n == "policy");
            let mut in_dev = false;
            for line in text.lines() {
                if line.starts_with('[') {
                    in_dev = line.trim() == "[dev-dependencies]";
                }
                if line.contains(FEATURE) && !line.trim_start().starts_with('#') {
                    let own_dev = is_policy && rel == "Cargo.toml" && in_dev;
                    let fuzz = is_policy && rel == "fuzz/Cargo.toml";
                    let declaration = is_policy && rel == "Cargo.toml" && line.contains("= []");
                    if !(own_dev || fuzz || declaration) {
                        offenders.push(format!("{}/{rel}: {line}", dir.display()));
                    }
                }
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:?}");
}

#[test]
fn g3_the_trusting_constructors_are_gated_in_the_source() {
    let src =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine.rs")).unwrap();
    for sig in ["pub fn new(", "pub fn with_directory("] {
        let at = src.find(sig).unwrap();
        let before = &src[..at];
        let attr = before
            .lines()
            .rev()
            .find(|l| l.trim_start().starts_with("#["))
            .unwrap();
        assert!(
            attr.contains(FEATURE),
            "{sig} must be behind the feature, found {attr}"
        );
    }
}
