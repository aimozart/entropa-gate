//! The policy crate stays inert: no network, no process spawning, no unsafe, no file writes;
//! policies come from strings. Guards that pass on the stubs and must keep passing.
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
fn n1_no_network_process_unsafe_file_access() {
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
    ] {
        assert!(!src.contains(banned), "found {banned} in crates/policy/src");
    }
}

#[test]
fn n1_the_manifest_has_no_http_cloud_or_kms_dependency() {
    let m = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap();
    for banned in ["reqwest", "hyper", "tokio", "aws-", "entropa-kms"] {
        assert!(!m.contains(banned), "Cargo.toml mentions {banned}");
    }
    assert!(
        m.contains("cedar-policy = \"=4.14.0\""),
        "the Cedar version stays pinned (ADR 0018)"
    );
}
