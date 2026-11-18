//! Guards that hold from the first commit: the council core is pure, small and free of internal names.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::Path;

fn read_dir(dir: &Path) -> Vec<(String, String)> {
    let mut out = vec![];
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(read_dir(&p));
        } else if p
            .extension()
            .is_some_and(|x| matches!(x.to_str(), Some("rs" | "json" | "toml")))
        {
            out.push((
                p.display().to_string(),
                std::fs::read_to_string(&p).unwrap(),
            ));
        }
    }
    out
}
fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}
fn no_comments(s: &str) -> String {
    s.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}
// Spelled backwards so this file never holds the names.
fn internal_names() -> Vec<String> {
    ["kcops", "yttocs", "tttocs", "ulus", "nietsnie"]
        .iter()
        .map(|s| s.chars().rev().collect())
        .collect()
}

#[test]
fn g1_the_source_is_pure_no_io_no_clock_no_environment_no_unsafe() {
    for (name, text) in read_dir(&manifest_dir().join("src")) {
        let code = no_comments(&text);
        for bad in [
            "std::fs",
            "File::",
            "OpenOptions",
            "TcpStream",
            "UdpSocket",
            "std::net",
            "reqwest",
            "hyper",
            "Command::new",
            "std::process",
            "SystemTime",
            "Instant::now",
            "std::env",
            "unsafe",
            "thread::sleep",
            "rand::",
        ] {
            assert!(!code.contains(bad), "{name} uses {bad}");
        }
    }
}

#[test]
fn g2_the_manifest_holds_no_network_cloud_or_model_dependency() {
    let m = std::fs::read_to_string(manifest_dir().join("Cargo.toml")).unwrap();
    for bad in [
        "reqwest", "hyper", "axum", "tokio", "ureq", "aws-", "google", "azure", "bedrock",
        "vertex", "openai", "rusqlite", "sqlx", "rand",
    ] {
        assert!(!m.contains(bad), "Cargo.toml mentions {bad}");
    }
}

#[test]
fn g3_no_crew_names_in_the_source_tests_or_vectors() {
    let names = internal_names();
    for dir in ["src", "tests"] {
        for (name, text) in read_dir(&manifest_dir().join(dir)) {
            let low = text.to_lowercase();
            for n in &names {
                assert!(!low.contains(n.as_str()), "{name} holds an internal name");
            }
        }
    }
}

#[test]
fn g4_no_source_file_is_over_five_hundred_lines() {
    for (name, text) in read_dir(&manifest_dir().join("src")) {
        assert!(
            text.lines().count() <= 500,
            "{name} has {} lines",
            text.lines().count()
        );
    }
}
