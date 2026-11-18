//! Test-plan rows P1-P8: the real binary over stdio. Until S2c the binary is a stub that exits 2.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

struct Session {
    child: std::process::Child,
    out: BufReader<std::process::ChildStdout>,
}

fn spawn() -> Session {
    let mut child = Command::new(env!("CARGO_BIN_EXE_entropa-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("ENTROPA_LOG_FILE")
        .env("ENTROPA_TRUSTED_PUBKEYS", "")
        .spawn()
        .unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    Session { child, out }
}

impl Session {
    fn send(&mut self, v: Value) {
        let stdin = self.child.stdin.as_mut().expect("stdin open");
        // a stub that already exited makes this write fail: report the stub's own message
        if writeln!(stdin, "{v}").is_err() {
            self.fail("server exited before reading the request");
        }
        let _ = stdin.flush();
    }
    fn recv(&mut self) -> Value {
        let mut line = String::new();
        let n = self.out.read_line(&mut line).unwrap();
        if n == 0 {
            self.fail("server closed stdout without answering");
        }
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("stdout line is not JSON: {line:?}"))
    }
    fn fail(&mut self, why: &str) -> ! {
        let mut err = String::new();
        if let Some(mut e) = self.child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut e, &mut err);
        }
        panic!("{why}; server stderr: {}", err.trim());
    }
}

fn init(s: &mut Session) {
    s.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}));
    let r = s.recv();
    assert_eq!(r["id"], 1, "{r}");
    s.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
}

#[test]
fn p1_p2_legacy_handshake_then_tools_list_in_the_fixed_order() {
    let mut s = spawn();
    s.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}));
    let r = s.recv();
    assert!(r["result"]["capabilities"]["tools"].is_object(), "{r}");
    s.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    s.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let r = s.recv();
    let names: Vec<_> = r["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, entropa_mcp::TOOL_NAMES.to_vec());
    for t in r["result"]["tools"].as_array().unwrap() {
        assert!(t["inputSchema"].is_object() && t["outputSchema"].is_object());
    }
}

#[test]
fn p3_modern_discover_and_per_request_meta() {
    let mut s = spawn();
    let meta = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}});
    s.send(json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta": meta}}));
    assert!(s.recv()["result"].is_object());
    s.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta": meta}}));
    assert!(s.recv()["result"]["tools"].is_array());
}

#[test]
fn p4_unknown_tool_and_malformed_calls_are_protocol_errors() {
    let mut s = spawn();
    init(&mut s);
    s.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}));
    assert_eq!(s.recv()["error"]["code"], -32602); // unknown tool: the spec's own example
                                                   // Malformed tools/call: the spec requires a JSON-RPC protocol error (not a tool result).
                                                   // rmcp 3.6.0 reports these as -32601 instead of -32602 (observed 2026-10-20, S2c), so both
                                                   // codes are accepted; the property that matters is "error, not result".
    for (id, params) in [
        (3, json!({"arguments":{}})),
        (4, json!({"name":"log_head","arguments":[]})),
    ] {
        s.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}));
        let r = s.recv();
        assert!(
            r.get("result").is_none(),
            "malformed call must not produce a result: {r}"
        );
        assert!(
            [-32601, -32602].contains(&r["error"]["code"].as_i64().unwrap()),
            "{r}"
        );
    }
}

#[test]
fn p5_p8_every_stdout_line_is_json_rpc_and_results_carry_structured_content_and_text() {
    let mut s = spawn();
    init(&mut s);
    s.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"log_head","arguments":{}}}));
    let r = s.recv();
    assert_eq!(r["jsonrpc"], "2.0");
    assert_eq!(r["id"], 2);
    let res = &r["result"];
    assert_eq!(res["isError"], true, "no log source: unavailable"); // execution error, not protocol error
    assert_eq!(res["structuredContent"]["error"], "unavailable");
    assert_eq!(res["content"][0]["type"], "text");
    let text: Value = serde_json::from_str(res["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, res["structuredContent"]);
}

#[test]
fn p6_closing_stdin_makes_the_process_exit_promptly() {
    let mut s = spawn();
    init(&mut s);
    drop(s.child.stdin.take());
    let start = std::time::Instant::now();
    let status = s.child.wait().unwrap();
    assert!(status.success(), "exit status {status}");
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn p7_responses_are_matched_by_id_not_position() {
    let mut s = spawn();
    init(&mut s);
    s.send(json!({"jsonrpc":"2.0","id":10,"method":"tools/list"}));
    s.send(json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"log_head","arguments":{}}}));
    let (a, b) = (s.recv(), s.recv());
    let ids: std::collections::BTreeSet<_> =
        [a["id"].as_i64().unwrap(), b["id"].as_i64().unwrap()].into();
    assert_eq!(ids, [10, 11].into());
}

impl Session {
    fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.child.stdin.as_mut().expect("stdin open");
        if stdin.write_all(bytes).is_err() {
            self.fail("server exited before reading the request");
        }
        let _ = stdin.flush();
    }
}

/// Reads responses until one has `id`, returning it. (Other lines are ignored.)
fn recv_id(s: &mut Session, id: i64) -> Value {
    for _ in 0..10 {
        let r = s.recv();
        if r["id"] == json!(id) {
            return r;
        }
    }
    panic!("no response with id {id}");
}

/// S2d / X2a: a request line over 1 MiB is refused with a protocol error, never processed, and
/// the server keeps working afterwards.
#[test]
fn x2a_an_oversize_request_line_is_refused_and_the_server_survives() {
    let mut s = spawn();
    init(&mut s);
    let huge = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{{\"name\":\"verify_checkpoint\",\"arguments\":{{\"checkpoint\":{{\"root\":\"{}\"}}}}}}}}\n",
        "a".repeat(2 * 1024 * 1024)
    );
    s.send_raw(huge.as_bytes());
    let r = s.recv();
    assert!(
        r.get("result").is_none(),
        "an oversize request must not produce a result: {}",
        &r.to_string()[..r.to_string().len().min(200)]
    );
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("request_too_large"),
        "{r}"
    );
    s.send(json!({"jsonrpc":"2.0","id":8,"method":"tools/list"}));
    assert!(recv_id(&mut s, 8)["result"]["tools"].is_array());
}

/// X2b/X2c: deep nesting, invalid UTF-8 and NUL bytes do not kill or hang the server.
#[test]
fn x2b_hostile_bytes_do_not_kill_the_server() {
    let mut s = spawn();
    init(&mut s);
    s.send_raw(format!("{}{}\n", "[".repeat(10_000), "]".repeat(10_000)).as_bytes());
    s.send_raw(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"\xff\xfe\"}\n");
    s.send_raw(b"\0\0\0\n");
    s.send(json!({"jsonrpc":"2.0","id":9,"method":"tools/list"}));
    assert!(recv_id(&mut s, 9)["result"]["tools"].is_array());
}

/// S2d/S2e: the modern list result carries caching hints, the legacy one does not.
#[test]
fn p9_modern_tools_list_has_ttl_and_cache_scope_legacy_does_not() {
    let mut s = spawn();
    let meta = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}});
    s.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta": meta}}));
    let modern = recv_id(&mut s, 2);
    assert!(modern["result"]["ttlMs"].is_number(), "{modern}");
    assert_eq!(modern["result"]["cacheScope"], "public");
    let mut legacy = spawn();
    init(&mut legacy);
    legacy.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}));
    let r = recv_id(&mut legacy, 3);
    assert!(r["result"].get("ttlMs").is_none(), "{r}");
}

/// S2e: an export file over 64 MiB is refused at startup; exactly 64 MiB is read (and then
/// rejected as invalid JSON, a different message), so the limit is neither off by one nor missing.
#[test]
fn p10_the_export_size_limit_is_64_mib() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let run = |len: u64| {
        let path = dir.join(format!("export-{len}.json"));
        std::fs::File::create(&path).unwrap().set_len(len).unwrap(); // sparse, costs no disk
        let out = Command::new(env!("CARGO_BIN_EXE_entropa-mcp"))
            .env("ENTROPA_LOG_FILE", &path)
            .env("ENTROPA_TRUSTED_PUBKEYS", "")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        std::fs::remove_file(&path).ok();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    let (code, err) = run(64 * 1024 * 1024 + 1);
    assert_eq!(code, Some(2));
    assert!(err.contains("larger than 64 MiB"), "{err}");
    let (code, err) = run(64 * 1024 * 1024);
    assert_eq!(code, Some(2));
    assert!(!err.contains("larger than 64 MiB"), "{err}");
    assert!(err.contains("ENTROPA_LOG_FILE"), "{err}");
}

/// S2e: the schemas the protocol layer advertises are the real ones, not empty objects.
#[test]
fn p11_advertised_schemas_are_the_real_ones() {
    let mut s = spawn();
    init(&mut s);
    s.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let r = recv_id(&mut s, 2);
    let tools = r["result"]["tools"].as_array().unwrap();
    let vr = tools
        .iter()
        .find(|t| t["name"] == "verify_receipt")
        .unwrap();
    assert_eq!(vr["inputSchema"]["required"], json!(["receipt"]));
    assert_eq!(vr["inputSchema"]["additionalProperties"], false);
    assert!(vr["outputSchema"]["properties"]["valid"].is_object());
    assert_eq!(vr["annotations"]["readOnlyHint"], true);
}
