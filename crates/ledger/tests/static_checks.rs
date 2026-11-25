//! The ledger core stays inert: no network, no process spawning, no unsafe, no environment or clock
//! access; keys come from the caller; and no internal name appears in the sources.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn sources() -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap())
        .collect()
}

#[test]
fn n1_no_network_process_unsafe_clock_or_environment_access() {
    let src = sources();
    for banned in [
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "reqwest",
        "Command::new",
        "unsafe ",
        "SystemTime",
        "Instant::now",
        "std::env",
        "getenv",
    ] {
        assert!(!src.contains(banned), "found {banned} in crates/ledger/src");
    }
}

#[test]
fn n1_the_manifest_has_no_http_or_cloud_dependency() {
    let m = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap();
    for banned in [
        "reqwest",
        "hyper",
        "tokio",
        "aws-",
        "azure",
        "entropa-kms",
        "entropa-api",
        "entropa-mcp",
    ] {
        assert!(!m.contains(banned), "Cargo.toml mentions {banned}");
    }
}

#[test]
fn n2_no_crew_name_in_the_sources() {
    let src = sources().to_lowercase();
    for name in ["kcops", "yttocs", "ulus", "niatpac"].map(|n| n.chars().rev().collect::<String>())
    {
        assert!(
            !src.contains(name.as_str()),
            "internal name {name:?} in crates/ledger/src"
        );
    }
}

#[test]
fn n3_the_limits_are_the_documented_ones() {
    assert_eq!(entropa_ledger::MAX_EVENT_BYTES, 16 * 1024);
    assert_eq!(entropa_ledger::MAX_BUNDLE_BYTES, 5 * 1024 * 1024);
    assert_eq!(entropa_ledger::EVENT_TYPE, "explorer.event");
}
