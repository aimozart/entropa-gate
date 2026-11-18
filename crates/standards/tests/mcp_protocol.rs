//! R1 task 4: the real `entropa-standards-mcp` binary over stdio, with hostile input. A fake node binary stands in for the signer so the records
//! can be read; one test uses the real `entropa-platinum` binary (when it is built) to prove each retrieval gives a record that verifies offline.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::seal;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

fn fx(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

struct World {
    _t: tempfile::TempDir,
    store: PathBuf,
    node: PathBuf,
    fake: PathBuf,
}

fn world() -> World {
    use sha2::{Digest, Sha256};
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    std::fs::create_dir(&src).unwrap();
    for n in [
        "oscal_mini.json",
        "eu_mini.txt",
        "pci_mini.txt",
        "html_mini.html",
    ] {
        std::fs::write(src.join(n), fx(n)).unwrap();
    }
    let sha = |n: &str| hex::encode(Sha256::digest(std::fs::read(src.join(n)).unwrap()));
    let spec = format!(
        r#"{{"corpus_version":"mcp-test-1","sources":[
 {{"standard":"SYN-OSCAL","std_version":"1","tier":"OPEN","format":"oscal","file":"oscal_mini.json","sha256":"{}"}},
 {{"standard":"SYN-EU","std_version":"1","tier":"OPEN","format":"eu_text","file":"eu_mini.txt","sha256":"{}"}},
 {{"standard":"SYN-PAY","std_version":"1","tier":"LICENSED","format":"pci_text","file":"pci_mini.txt","sha256":"{}"}},
 {{"standard":"SYN-HTML","std_version":"1","tier":"OPEN","format":"html","file":"html_mini.html","sha256":"{}"}}]}}"#,
        sha("oscal_mini.json"),
        sha("eu_mini.txt"),
        sha("pci_mini.txt"),
        sha("html_mini.html")
    );
    let store = t.path().join("store");
    seal::seal(
        &seal::parse_spec(&spec).unwrap(),
        &src,
        &store,
        &|_: &Path| Err("none".into()),
        None,
    )
    .unwrap();
    let node = t.path().join("node");
    std::fs::create_dir(&node).unwrap();
    let fake = t.path().join("fake-platinum.sh");
    std::fs::write(&fake, "#!/bin/sh\n# stands in for entropa-platinum: log-evidence NODE_DIR reads one record on stdin\ncat >> \"$2/records.log\"\necho >> \"$2/records.log\"\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    World {
        _t: t,
        store,
        node,
        fake,
    }
}

struct Session {
    child: Child,
    out: BufReader<ChildStdout>,
}

fn spawn_with(w: &World, bin: &Path, node: &Path, extra: &[(&str, &str)]) -> Session {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_entropa-standards-mcp"));
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("ENTROPA_STANDARDS_STORE", &w.store)
        .env("ENTROPA_STANDARDS_VERSIONS", "mcp-test-1")
        .env("ENTROPA_PLATINUM_BIN", bin)
        .env("ENTROPA_NODE_DIR", node);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    Session { child, out }
}
fn spawn(w: &World) -> Session {
    spawn_with(w, &w.fake, &w.node, &[])
}

impl Session {
    fn send(&mut self, v: Value) {
        self.send_raw(format!("{v}\n").as_bytes());
    }
    fn send_raw(&mut self, b: &[u8]) {
        let i = self.child.stdin.as_mut().unwrap();
        i.write_all(b).unwrap();
        let _ = i.flush();
    }
    fn recv(&mut self) -> Value {
        let mut line = String::new();
        assert!(
            self.out.read_line(&mut line).unwrap() > 0,
            "server closed stdout"
        );
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("stdout line is not JSON: {line:?}"))
    }
    fn init(&mut self) {
        self.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}));
        assert_eq!(self.recv()["id"], 1);
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    }
    fn call(&mut self, id: i64, name: &str, args: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}}));
        loop {
            let r = self.recv();
            if r["id"] == json!(id) {
                return r;
            }
        }
    }
    fn finish(mut self) -> (std::process::ExitStatus, String) {
        drop(self.child.stdin.take());
        let status = self.child.wait().unwrap();
        let mut err = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        (status, err)
    }
}

fn records(w: &World) -> Vec<Value> {
    std::fs::read_to_string(w.node.join("records.log"))
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn m1_handshake_then_tools_list_gives_four_read_only_tools_in_the_fixed_order() {
    let w = world();
    let mut s = spawn(&w);
    s.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}));
    assert!(s.recv()["result"]["capabilities"]["tools"].is_object());
    s.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    s.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let r = s.recv();
    let tools = r["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, entropa_standards::tools::TOOL_NAMES);
    for t in tools {
        assert!(t["inputSchema"].is_object() && t["outputSchema"].is_object());
        assert_eq!(t["annotations"]["readOnlyHint"], true, "{t}");
    }
    assert!(records(&w).is_empty(), "listing tools is not a retrieval");
}

#[test]
fn m2_a_search_returns_cited_untrusted_passages_and_writes_exactly_one_record() {
    let w = world();
    let mut s = spawn(&w);
    s.init();
    let r = s.call(2, "search", json!({"query": "Article 3 of SYN-EU"}));
    let sc = &r["result"]["structuredContent"];
    assert_eq!(
        (
            r["result"]["isError"].as_bool().unwrap_or(false),
            sc["verdict"].as_str()
        ),
        (false, Some("answered")),
        "{r}"
    );
    assert_eq!(
        (
            sc["passages"][0]["clause_id"].as_str(),
            sc["passages"][0]["untrusted"].as_bool()
        ),
        (Some("Art.3"), Some(true))
    );
    assert_eq!(sc["corpus_version"], "mcp-test-1");
    let text: Value =
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text, sc);
    let recs = records(&w);
    assert_eq!(recs.len(), 1);
    assert_eq!(
        (
            recs[0]["kind"].as_str(),
            recs[0]["label"].as_str(),
            recs[0]["decision"].as_str()
        ),
        (
            Some("evidence.access"),
            Some("retrieval_record"),
            Some("allow")
        )
    );
    assert!(
        !recs[0].to_string().contains("Article 3 of SYN-EU"),
        "the query text is never recorded"
    );
}

#[test]
fn m3_abstentions_invalid_arguments_and_unknown_tools_each_leave_one_record() {
    let w = world();
    let mut s = spawn(&w);
    s.init();
    let a = s.call(
        2,
        "search",
        json!({"query": "what is the airspeed velocity of an unladen swallow"}),
    );
    assert_eq!(a["result"]["structuredContent"]["verdict"], "not_in_corpus");
    let bad = s.call(3, "search", json!({"query": 5}));
    assert_eq!(
        (
            bad["result"]["isError"].clone(),
            bad["result"]["structuredContent"]["error"].clone()
        ),
        (json!(true), json!("invalid_arguments"))
    );
    let unk = s.call(4, "write_file", json!({"path": "/etc/passwd"}));
    assert_eq!(unk["error"]["code"], -32602, "{unk}");
    let recs = records(&w);
    assert_eq!(recs.len(), 3);
    assert_eq!(
        recs.iter()
            .map(|r| r["decision"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["deny", "deny", "deny"]
    );
}

#[test]
fn m4_hostile_lines_do_not_kill_the_server_and_the_next_valid_request_is_answered() {
    let w = world();
    let mut s = spawn(&w);
    s.init();
    let hostile: Vec<Vec<u8>> = vec![
        b"not json at all\n".to_vec(), b"{\n".to_vec(), b"[]\n".to_vec(), b"{\"jsonrpc\":\"2.0\"}\n".to_vec(), b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":42}\n".to_vec(),
        b"\xff\xfe\x00\x01 binary \x80\n".to_vec(), format!("{}\n", "[".repeat(5000)).into_bytes(),
        format!("{{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{{\"name\":\"search\",\"arguments\":{{\"query\":\"{}\"}}}}}}\n", "a".repeat(1_500_000)).into_bytes(),
        b"\n\n\n".to_vec(),
    ];
    for line in hostile {
        s.send_raw(&line);
    }
    let r = s.call(100, "search", json!({"query": "Article 2 of SYN-EU"}));
    assert_eq!(
        r["result"]["structuredContent"]["passages"][0]["clause_id"], "Art.2",
        "{r}"
    );
    let long = s.call(101, "search", json!({"query": "x".repeat(5000)}));
    assert_eq!(
        long["result"]["structuredContent"]["error"],
        "invalid_arguments"
    );
    let (status, _) = s.finish();
    assert!(status.success());
}

#[test]
fn m5_stdout_carries_only_json_rpc_and_stderr_never_carries_query_or_clause_text() {
    let w = world();
    let mut s = spawn(&w);
    s.init();
    let secret = "zebra-canary-query-text";
    let _ = s.call(
        2,
        "search",
        json!({"query": format!("Article 3 of SYN-EU {secret}")}),
    );
    let _ = s.call(
        3,
        "lookup_clause",
        json!({"standard": "SYN-PAY", "clause": "10.3.4"}),
    );
    let (status, err) = s.finish();
    assert!(status.success());
    assert!(
        !err.contains(secret)
            && !err.contains("cannot be changed")
            && !err.contains("Record-keeping"),
        "{err}"
    );
    for line in err.lines().filter(|l| l.starts_with('{')) {
        let v: Value = serde_json::from_str(line).unwrap();
        assert!(v["tool"].is_string() && v["outcome"].is_string() && v["ms"].is_number());
    }
}

#[test]
fn m6_closing_stdin_ends_the_process_promptly_with_status_zero() {
    let w = world();
    let mut s = spawn(&w);
    s.init();
    let t = std::time::Instant::now();
    let (status, _) = s.finish();
    assert!(status.success() && t.elapsed().as_secs() < 5);
}

#[test]
fn m7_the_server_refuses_to_start_without_a_sink_a_sealed_corpus_or_an_intact_store() {
    let w = world();
    let run = |envs: &[(&str, &str)], remove: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_entropa-standards-mcp"));
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for r in remove {
            c.env_remove(r);
        }
        for (k, v) in envs {
            c.env(k, v);
        }
        c.output().unwrap()
    };
    let ok_env = [
        ("ENTROPA_STANDARDS_STORE", w.store.to_str().unwrap()),
        ("ENTROPA_STANDARDS_VERSIONS", "mcp-test-1"),
        ("ENTROPA_PLATINUM_BIN", w.fake.to_str().unwrap()),
        ("ENTROPA_NODE_DIR", w.node.to_str().unwrap()),
    ];
    for drop in [
        "ENTROPA_STANDARDS_STORE",
        "ENTROPA_PLATINUM_BIN",
        "ENTROPA_NODE_DIR",
    ] {
        let envs: Vec<(&str, &str)> = ok_env.iter().filter(|(k, _)| *k != drop).cloned().collect();
        let o = run(&envs, &[drop]);
        assert_eq!(
            o.status.code(),
            Some(2),
            "without {drop}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    let mut bad_version = ok_env.to_vec();
    bad_version[1] = ("ENTROPA_STANDARDS_VERSIONS", "no-such-version");
    assert_eq!(run(&bad_version, &[]).status.code(), Some(2));
    let f = w.store.join("mcp-test-1/clauses.jsonl");
    let orig = std::fs::read_to_string(&f).unwrap();
    std::fs::write(&f, orig.replacen("Subject matter", "Subject matteR", 1)).unwrap();
    let o = run(&ok_env, &[]);
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        String::from_utf8_lossy(&o.stderr)
            .to_lowercase()
            .contains("tamper")
            || String::from_utf8_lossy(&o.stderr).contains("hash")
    );
}

#[test]
fn m8_if_the_record_cannot_be_written_the_server_returns_no_answer() {
    let w = world();
    let broken = w._t.path().join("broken.sh");
    std::fs::write(&broken, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut s = spawn_with(&w, &broken, &w.node, &[]);
    s.init();
    let r = s.call(2, "search", json!({"query": "Article 3 of SYN-EU"}));
    assert_eq!(r["result"]["isError"], true);
    assert_eq!(r["result"]["structuredContent"]["error"], "record_failed");
    assert!(
        !r.to_string().contains("traceability") && !r.to_string().contains("passages"),
        "{r}"
    );
}

#[test]
fn m9_the_server_works_with_no_network_at_all() {
    // run it inside an empty network namespace when the system allows that; otherwise say so (a skipped check is not a proof)
    if Command::new("unshare")
        .args(["--net", "--map-root-user", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let w = world();
        let mut child = Command::new("unshare")
            .args([
                "--net",
                "--map-root-user",
                env!("CARGO_BIN_EXE_entropa-standards-mcp"),
            ])
            .env("ENTROPA_STANDARDS_STORE", &w.store)
            .env("ENTROPA_STANDARDS_VERSIONS", "mcp-test-1")
            .env("ENTROPA_PLATINUM_BIN", &w.fake)
            .env("ENTROPA_NODE_DIR", &w.node)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let mut s = Session { child, out };
        s.init();
        assert_eq!(
            s.call(2, "search", json!({"query": "Article 3 of SYN-EU"}))["result"]
                ["structuredContent"]["verdict"],
            "answered"
        );
    } else {
        eprintln!("m9: unshare --net is not permitted here; the no-network behaviour is covered by the static checks only");
    }
}

#[test]
fn m10_with_the_real_node_binary_every_retrieval_gives_a_record_that_verifies_offline() {
    let platinum =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/entropa-platinum");
    if !platinum.exists() {
        eprintln!("m10: entropa-platinum is not built here (./run-cargo.sh build --release -p entropa-platinum); skipped");
        return;
    }
    let w = world();
    let node = w._t.path().join("real-node");
    assert!(Command::new(&platinum)
        .arg("init")
        .arg(&node)
        .output()
        .unwrap()
        .status
        .success());
    let mut s = spawn_with(&w, &platinum, &node, &[]);
    s.init();
    let _ = s.call(2, "search", json!({"query": "Article 3 of SYN-EU"}));
    let _ = s.call(
        3,
        "search",
        json!({"query": "what is the airspeed velocity of an unladen swallow"}),
    );
    let _ = s.call(4, "cite_check", json!({"standard": "SYN-EU", "clause": "Art.3", "version": "mcp-test-1", "hash": "f".repeat(64)}));
    let _ = s.call(5, "list_versions", json!({}));
    let (status, _) = s.finish();
    assert!(status.success());
    let v = Command::new(&platinum)
        .arg("verify-evidence")
        .arg(&node)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&v.stdout).contains("OK records=4 checkpoints=4"),
        "{}{}",
        String::from_utf8_lossy(&v.stdout),
        String::from_utf8_lossy(&v.stderr)
    );
    let e = Command::new(&platinum)
        .arg("export-evidence")
        .arg(&node)
        .output()
        .unwrap();
    let exp: Value = serde_json::from_slice(&e.stdout).unwrap();
    let plain: Vec<&str> = exp["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["plain"].as_str().unwrap())
        .collect();
    assert!(
        plain[0].contains("Retrieval:") && plain[0].contains("returned"),
        "{plain:?}"
    );
    assert!(plain[1].contains("not in the corpus"), "{plain:?}");
    assert!(exp["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["label"] == "retrieval_record"));
}
