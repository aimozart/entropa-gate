//! Test-plan rows N1 and N3: the crate must not contain write paths, process spawns, stdout
//! prints or unsafe code. These are guards that pass on the stubs and keep passing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn sources() -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut all = String::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "rs") {
            all += &std::fs::read_to_string(p).unwrap();
        }
    }
    all
}

#[test]
fn n1_no_write_paths_process_spawns_stdout_prints_or_unsafe() {
    let src = sources();
    for banned in [
        "fs::write",
        "File::create",
        "OpenOptions",
        "remove_file",
        "Command::new",
        "unsafe ",
        "TcpListener",
        "UdpSocket",
    ] {
        assert!(!src.contains(banned), "found {banned} in crates/mcp/src");
    }
    // stdout prints: `println!`/`print!` but not `eprintln!`/`eprint!`
    for mac in ["println!", "print!"] {
        for (i, _) in src.match_indices(mac) {
            let prev = src[..i].chars().last();
            assert!(
                prev == Some('e'),
                "stdout print `{mac}` found in crates/mcp/src"
            );
        }
    }
}

#[test]
fn n3_the_manifest_has_no_cloud_or_http_dependency_in_v1() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap();
    for banned in ["entropa-kms", "aws-", "reqwest", "hyper", "tokio"] {
        // tokio/rmcp arrive in S2c with their own ADR; this guard names what must never appear
        if banned == "tokio" {
            continue;
        }
        assert!(!manifest.contains(banned), "Cargo.toml mentions {banned}");
    }
}
