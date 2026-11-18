//! R1 task 4: static proof that the server has no network egress, spawns nothing but the record sink, and has no write path. These read the
//! manifest, the lockfile and the sources; they do not run the server.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|_| panic!("cannot read {}", p.display()))
}
fn sources() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    fn walk(d: &Path, base: &Path, out: &mut BTreeMap<String, String>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, base, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.insert(
                    p.strip_prefix(base).unwrap().to_string_lossy().to_string(),
                    std::fs::read_to_string(&p).unwrap(),
                );
            }
        }
    }
    walk(&root().join("src"), &root(), &mut out);
    out
}

fn lock_closure(start: &str) -> BTreeSet<String> {
    let lock = read(&root().join("../../Cargo.lock"));
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for blk in lock.split("[[package]]").skip(1) {
        let name = blk
            .lines()
            .find_map(|l| l.strip_prefix("name = \""))
            .and_then(|l| l.strip_suffix('"'))
            .unwrap()
            .to_string();
        let deps: BTreeSet<String> = blk
            .split("dependencies = [")
            .nth(1)
            .map(|d| {
                d.split(']')
                    .next()
                    .unwrap()
                    .lines()
                    .filter_map(|l| {
                        l.trim()
                            .trim_end_matches(',')
                            .trim_matches('"')
                            .split_whitespace()
                            .next()
                            .map(String::from)
                    })
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        graph.entry(name).or_default().extend(deps);
    }
    let (mut seen, mut stack) = (BTreeSet::new(), vec![start.to_string()]);
    while let Some(x) = stack.pop() {
        if seen.insert(x.clone()) {
            stack.extend(graph.get(&x).cloned().unwrap_or_default());
        }
    }
    seen
}

#[test]
fn s1_no_http_or_tls_client_crate_is_anywhere_in_the_dependency_closure() {
    let c = lock_closure("entropa-standards");
    assert!(
        c.contains("rmcp") && c.contains("tokio"),
        "the closure was computed"
    );
    for forbidden in [
        "reqwest",
        "hyper",
        "hyper-util",
        "h2",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
        "native-tls",
        "rustls",
        "tokio-rustls",
        "openssl",
        "openssl-sys",
        "axum",
        "tonic",
        "tungstenite",
        "aws-sdk-s3",
        "google-cloud-storage",
    ] {
        assert!(
            !c.contains(forbidden),
            "{forbidden} is in the dependency closure of entropa-standards"
        );
    }
}

#[test]
fn s2_tokio_is_built_without_its_net_feature_and_no_full_feature_set() {
    let m = read(&root().join("Cargo.toml"));
    let tokio_line = m
        .lines()
        .find(|l| l.trim_start().starts_with("tokio"))
        .expect("tokio is a dependency");
    assert!(
        !tokio_line.contains("\"net\"")
            && !tokio_line.contains("\"full\"")
            && !tokio_line.contains("\"process\""),
        "{tokio_line}"
    );
    let rmcp_line = m
        .lines()
        .find(|l| l.trim_start().starts_with("rmcp"))
        .expect("rmcp is a dependency");
    assert!(
        !rmcp_line.contains("http")
            && !rmcp_line.contains("client")
            && rmcp_line.contains("default-features = false"),
        "{rmcp_line}"
    );
}

#[test]
fn s3_no_network_or_socket_api_appears_in_any_source_file() {
    for (name, text) in sources() {
        for api in [
            "std::net",
            "tokio::net",
            "TcpStream",
            "TcpListener",
            "UdpSocket",
            "UnixStream",
            "UnixListener",
            "reqwest",
            "hyper::",
        ] {
            assert!(!text.contains(api), "{name} uses {api}");
        }
    }
}

#[test]
fn s4_the_only_process_spawns_are_the_record_sink_and_the_cli_pdf_extractor() {
    for (name, text) in sources() {
        let spawns = text.contains("Command::new") || text.contains("process::Command");
        let allowed = name == "src/records.rs" || name == "src/main.rs";
        assert!(!spawns || allowed, "{name} spawns a process");
    }
    let main = read(&root().join("src/main.rs"));
    assert_eq!(
        main.matches("Command::new").count(),
        1,
        "main.rs spawns only pdftotext"
    );
    assert!(main.contains("Command::new(\"pdftotext\")"));
    assert_eq!(
        read(&root().join("src/records.rs"))
            .matches("Command::new")
            .count(),
        1,
        "records.rs spawns only the node binary"
    );
}

#[test]
fn s5_the_server_path_has_no_write_to_the_file_system() {
    let server_path = [
        "src/tools.rs",
        "src/retrieve.rs",
        "src/text.rs",
        "src/corpus.rs",
        "src/bin/entropa-standards-mcp.rs",
    ];
    let src = sources();
    for f in server_path {
        let text = src.get(f).unwrap_or_else(|| panic!("{f} is missing"));
        for w in [
            "fs::write",
            "File::create",
            "OpenOptions",
            "create_dir",
            "remove_file",
            "remove_dir",
            "fs::rename",
            "fs::copy",
            "set_permissions",
            "write_all",
        ] {
            assert!(!text.contains(w), "{f} contains {w}");
        }
    }
}

#[test]
fn s6_the_tool_names_contain_no_write_verb_and_the_binary_registers_no_tool_outside_the_core() {
    let bin = read(&root().join("src/bin/entropa-standards-mcp.rs"));
    assert!(
        bin.contains("Server::tools()")
            && bin.contains("TOOL_NAMES")
            && bin.contains("read_only(true)")
    );
    for verb in [
        "write", "delete", "remove", "exec", "ingest", "seal", "emit", "update", "create", "put",
        "post",
    ] {
        assert!(
            entropa_standards::tools::TOOL_NAMES
                .iter()
                .all(|n| !n.contains(verb)),
            "{verb}"
        );
    }
}
