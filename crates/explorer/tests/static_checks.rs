//! Guards that pass already: the crate has no write path, no network client, no clock, no internal names.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use std::path::Path;

fn sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .map(|p| {
            (
                p.display().to_string(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect()
}

// Spelled backwards so this file itself never holds the names.
fn internal_names() -> Vec<String> {
    ["kcops", "yttocs", "tttocs", "ulus", "nietsnie"]
        .iter()
        .map(|s| s.chars().rev().collect())
        .collect()
}

fn no_comments(s: &str) -> String {
    s.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn s1_no_write_paths_in_the_source() {
    for (name, text) in sources() {
        let code = no_comments(&text);
        for bad in [
            "File::create",
            "OpenOptions",
            "fs::write",
            "remove_file",
            "remove_dir",
            "create_dir",
            "fs::rename",
            "fs::copy",
            "set_permissions",
        ] {
            assert!(!code.contains(bad), "{name} uses {bad}");
        }
    }
}

#[test]
fn s2_no_network_client_no_process_no_ambient_clock_or_environment() {
    for (name, text) in sources() {
        let code = no_comments(&text);
        for bad in [
            "TcpStream",
            "TcpListener",
            "UdpSocket",
            "reqwest",
            "hyper",
            "ureq",
            "std::net",
            "Command::new",
            "std::process",
            "SystemTime",
            "Instant::now",
            "std::env",
            "unsafe",
        ] {
            assert!(!code.contains(bad), "{name} uses {bad}");
        }
    }
}

#[test]
fn s3_no_http_or_cloud_dependency_in_the_manifest() {
    let m =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    for bad in [
        "reqwest", "hyper", "axum", "actix", "tokio", "ureq", "aws-", "google", "azure",
        "rusqlite", "sqlx",
    ] {
        assert!(!m.contains(bad), "Cargo.toml mentions {bad}");
    }
}

#[test]
fn s4_no_crew_names_in_the_source_the_fixture_or_the_golden_responses() {
    let names = internal_names();
    for (name, text) in sources() {
        let low = text.to_lowercase();
        for n in &names {
            assert!(!low.contains(n.as_str()), "{name} holds an internal name");
        }
    }
    for (what, text) in [
        ("fixture", include_str!("golden/bundle_seed1_n5.json")),
        ("golden", include_str!("golden/responses.json")),
    ] {
        let low = text.to_lowercase();
        for n in &names {
            assert!(!low.contains(n.as_str()), "{what} holds an internal name");
        }
    }
}

#[test]
fn s5_the_source_never_names_a_cookie_or_a_session() {
    for (name, text) in sources() {
        let code = no_comments(&text).to_lowercase();
        assert!(!code.contains("set-cookie"), "{name}");
        assert!(
            !code.contains("localstorage") && !code.contains("sessionstorage"),
            "{name}"
        );
    }
}
