//! Guards that hold from the first commit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::Path;

#[test]
fn g1_the_crate_has_no_io_network_clock_or_randomness_and_no_stored_records() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let text = std::fs::read_to_string(&p).unwrap();
        let code: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for bad in [
            "std::fs",
            "File::",
            "std::net",
            "reqwest",
            "Command::new",
            "SystemTime",
            "Instant::now",
            "std::env",
            "unsafe",
            "rand::",
            "include_str!",
            "include_bytes!",
        ] {
            assert!(!code.contains(bad), "{} uses {bad}", p.display());
        }
    }
}

#[test]
fn g2_the_manifest_has_only_hashing_dependencies() {
    let m =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps = m.split("[dev-dependencies]").next().unwrap();
    for ok_only in ["blake3", "hex"] {
        assert!(deps.contains(ok_only));
    }
    for bad in ["reqwest", "tokio", "rand", "serde", "chrono", "uuid"] {
        assert!(!deps.contains(bad), "{bad}");
    }
}
