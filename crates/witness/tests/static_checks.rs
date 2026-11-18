//! The witness core stays inert: no network, no process spawning, no unsafe, no file or cloud access,
//! no secret handling; time and state come from the caller. Guards that pass on the stubs and must keep passing.
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
fn n1_no_network_process_unsafe_file_clock_or_environment_access() {
    let src = sources();
    for banned in [
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "reqwest",
        "Command::new",
        "unsafe ",
        "fs::write",
        "fs::read",
        "File::create",
        "File::open",
        "OpenOptions",
        "remove_file",
        "SystemTime",
        "Instant::now",
        "std::env",
        "getenv",
    ] {
        assert!(
            !src.contains(banned),
            "found {banned} in crates/witness/src"
        );
    }
}

#[test]
fn n1_the_manifest_has_no_http_cloud_or_kms_dependency() {
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
        "cedar",
    ] {
        assert!(!m.contains(banned), "Cargo.toml mentions {banned}");
    }
}

#[test]
fn n2_the_limits_are_the_documented_ones() {
    assert_eq!(entropa_witness::MAX_REQUEST_BYTES, 64 * 1024);
    assert_eq!(entropa_witness::MAX_PROOF_LEN, 64);
    assert_eq!(entropa_witness::STATEMENT_TYPE, "witness.cosign");
    assert_eq!(entropa_witness::NO_PREVIOUS_ROOT.len(), 64);
}
