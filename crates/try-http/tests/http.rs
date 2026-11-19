//! LS3b red tests, part 2: the real binary on the LOOPBACK interface (a stage record (not published); loopback sockets are allowed for this stage only). Raw TCP, so the bytes on the wire are exact.
//! Expected statuses and bodies come from the plan's table (LS3b.md sections 2 to 5), not from the code. Synthetic words only; canary strings are built from parts at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ORIGIN: &str = "https://try.example.test";
const GOOD: &str = r#"{"text":"Please summarise the retention clause.","tier":"T1"}"#;

struct Server {
    child: Child,
    port: u16,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn pipe(r: impl Read + Send + 'static, sink: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut r = r;
        let mut buf = [0u8; 4096];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
}

/// Start the binary with the base arguments plus `extra` (a flag in `extra` replaces the base flag of the same name; a flag with the value `-` is dropped).
fn start_with(extra: &[(&str, &str)]) -> Result<Server, String> {
    let mut args: Vec<(String, String)> = vec![
        ("--listen".into(), "127.0.0.1:0".into()),
        ("--trusted-hops".into(), "1".into()),
        ("--allow-origin".into(), ORIGIN.into()),
        ("--stats-secs".into(), "1".into()),
    ];
    for (k, v) in extra {
        args.retain(|(a, _)| a != k);
        if *v != "-" {
            args.push((k.to_string(), v.to_string()));
        }
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_entropa-try-http"))
        .args(args.iter().flat_map(|(k, v)| [k.clone(), v.clone()]))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let (out, err) = (
        Arc::new(Mutex::new(String::new())),
        Arc::new(Mutex::new(String::new())),
    );
    pipe(child.stdout.take().unwrap(), out.clone());
    pipe(child.stderr.take().unwrap(), err.clone());
    let t = Instant::now();
    loop {
        let s = out.lock().unwrap().clone();
        if let Some(line) = s
            .lines()
            .find(|l| l.starts_with("entropa-try-http listening "))
        {
            let addr = line.split_whitespace().nth(2).ok_or("no address")?;
            let port: u16 = addr
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
                .ok_or("no port")?;
            return Ok(Server {
                child,
                port,
                out,
                err,
            });
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("exited with {status}: {}", err.lock().unwrap()));
        }
        if t.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            return Err("no start line within 5 s".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn start(extra: &[(&str, &str)]) -> Server {
    start_with(extra).unwrap()
}

#[derive(Debug, Default)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}
impl Resp {
    fn h(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read one response (or none if the server closed without answering).
fn read_resp(s: &mut TcpStream, limit: Duration) -> Option<Resp> {
    let t = Instant::now();
    s.set_read_timeout(Some(Duration::from_millis(200))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
        if let Some(r) = parse(&buf) {
            return Some(r);
        }
        if t.elapsed() > limit {
            break;
        }
    }
    parse(&buf).or_else(|| parse_eof(&buf))
}
fn split(buf: &[u8]) -> Option<(String, Vec<u8>)> {
    let i = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((
        String::from_utf8_lossy(&buf[..i]).into_owned(),
        buf[i + 4..].to_vec(),
    ))
}
fn head(h: &str) -> Option<(u16, Vec<(String, String)>)> {
    let mut lines = h.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Some((status, headers))
}
fn parse(buf: &[u8]) -> Option<Resp> {
    let (h, body) = split(buf)?;
    let (status, headers) = head(&h)?;
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());
    match len {
        Some(n) if body.len() >= n => Some(Resp {
            status,
            headers,
            body: String::from_utf8_lossy(&body[..n]).into_owned(),
        }),
        Some(_) => None,
        None => {
            // no length: a body-less response (204, 404 with no body) is complete when the head is
            if status == 204 || status == 404 || status == 405 || status == 403 || status == 431 {
                Some(Resp {
                    status,
                    headers,
                    body: String::from_utf8_lossy(&body).into_owned(),
                })
            } else {
                None
            }
        }
    }
}
fn parse_eof(buf: &[u8]) -> Option<Resp> {
    let (h, body) = split(buf)?;
    let (status, headers) = head(&h)?;
    Some(Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn send(port: u16, bytes: &[u8]) -> Option<Resp> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(bytes).ok()?;
    read_resp(&mut s, Duration::from_secs(8))
}
fn get(port: u16, path: &str) -> Resp {
    send(
        port,
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .expect("a response")
}
fn post(port: u16, xff: Option<&str>, origin: Option<&str>, body: &str) -> Resp {
    let mut h = format!("POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    if let Some(x) = xff {
        h += &format!("X-Forwarded-For: {x}\r\n");
    }
    if let Some(o) = origin {
        h += &format!("Origin: {o}\r\n");
    }
    send(port, format!("{h}\r\n{body}").as_bytes()).expect("a response")
}
fn json(r: &Resp) -> serde_json::Value {
    serde_json::from_str(&r.body).unwrap_or_else(|_| panic!("not JSON: {:?}", r))
}

#[test]
fn h1_the_binary_refuses_to_start_without_hops_or_a_single_allowed_origin() {
    for (name, extra) in [
        ("no trusted-hops", vec![("--trusted-hops", "-")]),
        ("no allow-origin", vec![("--allow-origin", "-")]),
        ("star origin", vec![("--allow-origin", "*")]),
        (
            "wildcard host",
            vec![("--allow-origin", "https://*.example.test")],
        ),
        (
            "origin with a path",
            vec![("--allow-origin", "https://try.example.test/")],
        ),
        ("no host", vec![("--allow-origin", "https://")]),
        ("no host, http", vec![("--allow-origin", "http://")]),
        (
            "a path after the host",
            vec![("--allow-origin", "https://try.example.test/app")],
        ),
        ("zero concurrency", vec![("--concurrency", "0")]),
        ("zero stats interval", vec![("--stats-secs", "0")]),
        ("hops not a number", vec![("--trusted-hops", "many")]),
        (
            "two origins",
            vec![(
                "--allow-origin",
                "https://a.example.test,https://b.example.test",
            )],
        ),
    ] {
        let e = start_with(&extra)
            .err()
            .unwrap_or_else(|| panic!("{name}: it started"));
        assert!(e.contains("exited with"), "{name}: {e}");
        assert!(
            e.contains("exit status: 2") || e.contains("exit code: 2"),
            "{name}: must exit with 2: {e}"
        );
    }
    let s = start(&[]);
    assert_eq!(get(s.port, "/healthz").status, 200);
}

#[test]
fn h2_routes_and_methods() {
    let s = start(&[]);
    let r = get(s.port, "/healthz");
    assert_eq!((r.status, r.body.as_str()), (200, ""));
    for path in ["/", "/static/app.js", "/try/extra", "/healthz/x", "/TRY"] {
        let r = get(s.port, path);
        assert_eq!((r.status, r.body.as_str()), (404, ""), "{path}");
        assert!(r.h("set-cookie").is_none() && r.h("location").is_none());
    }
    assert_eq!(get(s.port, "/try").status, 405);
    assert_eq!(
        send(
            s.port,
            b"POST /healthz HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap()
        .status,
        405
    );
    assert_eq!(
        send(
            s.port,
            b"DELETE /try HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap()
        .status,
        405
    );
}

#[test]
fn h3_a_valid_request_gets_the_handler_answer_with_a_signed_record() {
    let s = start(&[]);
    let r = post(s.port, Some("198.51.100.7"), None, GOOD);
    assert_eq!(r.status, 200, "{r:?}");
    assert!(r
        .h("content-type")
        .unwrap_or("")
        .starts_with("application/json"));
    assert_eq!(r.h("cache-control"), Some("no-store"));
    let j = json(&r);
    assert_eq!(j["label"], "mock data, real signed records");
    assert_eq!(j["decision"], "allow");
    assert!(j["record"]["event"].as_str().unwrap().len() > 100);
    // a handler error passes through with its own status and closed code
    let r = post(s.port, Some("198.51.100.8"), None, "not json");
    assert_eq!(
        (r.status, json(&r)["error"].as_str()),
        (400, Some("not_json"))
    );
}

fn ten_ok_then_429(port: u16, xff_for: impl Fn(usize) -> Option<String>) {
    for i in 0..10 {
        let x = xff_for(i);
        let r = post(port, x.as_deref(), None, GOOD);
        assert_eq!(r.status, 200, "request {i} ({x:?}): {r:?}");
    }
    let x = xff_for(10);
    let r = post(port, x.as_deref(), None, GOOD);
    assert_eq!(
        r.status, 429,
        "the 11th request of the same client ({x:?}): {r:?}"
    );
    assert!(r.h("retry-after").is_some());
}

#[test]
fn h4_a_forged_forwarded_for_does_not_change_the_bucket_but_a_different_real_entry_does() {
    let s = start(&[]);
    ten_ok_then_429(s.port, |i| {
        Some(format!("10.0.{i}.1, 172.16.{i}.9, 203.0.113.9"))
    });
    // a different real (rightmost) entry is another client
    assert_eq!(
        post(s.port, Some("10.0.0.1, 203.0.113.10"), None, GOOD).status,
        200
    );
}

#[test]
fn h5_with_two_hops_the_second_entry_from_the_right_is_the_key() {
    let s = start(&[("--trusted-hops", "2")]);
    ten_ok_then_429(s.port, |i| {
        Some(format!("10.0.{i}.1, 203.0.113.50, 192.0.2.{}", i + 1))
    });
}

#[test]
fn h6_a_missing_short_or_non_ip_header_falls_back_to_the_peer_address_and_they_share_one_bucket() {
    let s = start(&[("--trusted-hops", "2")]);
    let variants: [Option<&str>; 5] = [
        None,
        Some("203.0.113.1"),
        Some("not-an-ip, 203.0.113.2"),
        Some("1.1.1.1:99, 203.0.113.3"),
        Some(""),
    ];
    for i in 0..10 {
        let r = post(s.port, variants[i % 5], None, GOOD);
        assert_eq!(r.status, 200, "request {i}: {r:?}");
    }
    assert_eq!(
        post(s.port, None, None, GOOD).status,
        429,
        "the peer bucket is full"
    );
}

#[test]
fn h7_two_ipv6_addresses_in_one_64_share_a_bucket_and_another_64_does_not() {
    let s = start(&[]);
    ten_ok_then_429(s.port, |i| {
        Some(format!("2001:db8:1:2:{:x}::{:x}", i + 1, i + 7))
    });
    assert_eq!(
        post(s.port, Some("2001:db8:1:3::1"), None, GOOD).status,
        200
    );
}

#[test]
fn h8_header_limits() {
    let s = start(&[]);
    let big = "a".repeat(9 * 1024);
    let r = send(s.port, format!("POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Forwarded-For: 203.0.113.61\r\nX-Big: {big}\r\nConnection: close\r\n\r\n{GOOD}", GOOD.len()).as_bytes());
    assert!(
        r.as_ref()
            .is_none_or(|r| r.status == 431 || r.status == 400),
        "9 KiB of headers must be refused: {r:?}"
    );
    let many: String = (0..70).map(|i| format!("X-H{i}: v\r\n")).collect();
    let r = send(s.port, format!("POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Forwarded-For: 203.0.113.62\r\n{many}Connection: close\r\n\r\n{GOOD}", GOOD.len()).as_bytes());
    assert!(
        r.as_ref()
            .is_none_or(|r| r.status == 431 || r.status == 400),
        "70 headers must be refused: {r:?}"
    );
    let some: String = (0..20).map(|i| format!("X-H{i}: v\r\n")).collect();
    let r = send(s.port, format!("POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{some}X-Forwarded-For: 203.0.113.77\r\nConnection: close\r\n\r\n{GOOD}", GOOD.len()).as_bytes()).unwrap();
    assert_eq!(r.status, 200, "20 small headers are fine: {r:?}");
}

#[test]
fn h9_a_big_body_is_refused_without_reading_it() {
    let s = start(&[]);
    // a declared length of 1 GiB: refused at once, before any body byte is sent
    let t = Instant::now();
    let r = send(s.port, b"POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1073741824\r\nConnection: close\r\n\r\n").unwrap();
    assert_eq!(
        (r.status, json(&r)["error"].as_str()),
        (413, Some("too_large"))
    );
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "no waiting for a body that was never sent"
    );
    // a body just over the limit
    let body = format!(r#"{{"text":"{}","tier":"T1"}}"#, "a".repeat(5000));
    assert_eq!(post(s.port, Some("203.0.113.20"), None, &body).status, 413);
    // a chunked body with a declared 1 GiB chunk and ONE byte of it, then silence: it must not wait for the rest
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.write_all(b"POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n40000000\r\n{").unwrap();
    let t = Instant::now();
    let r = read_resp(&mut c, Duration::from_secs(6)).expect("an answer, not a hang");
    assert!(r.status == 408 || r.status == 413, "{r:?}");
    assert!(
        t.elapsed() < Duration::from_secs(4),
        "answered after {:?}",
        t.elapsed()
    );
    // a chunked body with a declared 1 GiB chunk that sends 8 KiB at once and then goes silent: refused with 413 as soon as the limit is passed, not after the body timeout
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.write_all(format!("POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n40000000\r\n{}", "a".repeat(8192)).as_bytes()).unwrap();
    let t = Instant::now();
    let r = read_resp(&mut c, Duration::from_secs(6)).expect("an answer");
    assert_eq!(r.status, 413, "{r:?}");
    assert!(
        t.elapsed() < Duration::from_millis(1200),
        "answered after {:?}: it waited for the rest of the body",
        t.elapsed()
    );
    // a normal chunked body works
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    let (a, b) = GOOD.split_at(10);
    c.write_all(format!("POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nX-Forwarded-For: 203.0.113.21\r\nConnection: close\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n", a.len(), b.len()).as_bytes()).unwrap();
    assert_eq!(
        read_resp(&mut c, Duration::from_secs(5)).unwrap().status,
        200
    );
}

#[test]
fn h10_slow_senders_are_cut_off() {
    let s = start(&[]);
    // headers dribbled one byte at a time: the connection is closed within about 2 s of the first byte (limit 2 s) and never answered with 200
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    let t = Instant::now();
    let slow = b"POST /try HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n";
    let mut closed = false;
    for b in slow.iter().cycle().take(60) {
        if c.write_all(&[*b]).is_err() {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
        c.set_read_timeout(Some(Duration::from_millis(1))).ok();
        let mut x = [0u8; 1];
        if matches!(c.read(&mut x), Ok(0)) {
            closed = true;
            break;
        }
        if t.elapsed() > Duration::from_secs(5) {
            break;
        }
    }
    assert!(closed, "a header dribble must be cut off");
    assert!(
        t.elapsed() < Duration::from_millis(3500),
        "cut off after {:?}",
        t.elapsed()
    );
    // a complete header and a body that arrives one byte per 400 ms: 408 within the time limit
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.write_all(b"POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 50\r\nConnection: close\r\n\r\n").unwrap();
    let t = Instant::now();
    let mut r = None;
    for _ in 0..12 {
        if c.write_all(b"{").is_err() {
            break;
        }
        if let Some(x) = read_resp(&mut c, Duration::from_millis(400)) {
            r = Some(x);
            break;
        }
    }
    let r = r.expect("an answer to a slow body");
    assert_eq!(r.status, 408, "{r:?}");
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
}

#[test]
fn h11_the_ninth_concurrent_request_gets_503_busy() {
    let s = start(&[]);
    // eight requests that announce a body and then wait: each holds one of the eight places until the body timeout
    let mut held = Vec::new();
    for i in 0..8 {
        let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
        c.write_all(format!("POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 40\r\nX-Forwarded-For: 203.0.113.{}\r\nConnection: close\r\n\r\n", 100 + i).as_bytes()).unwrap();
        held.push(c);
    }
    std::thread::sleep(Duration::from_millis(400));
    let r = post(s.port, Some("203.0.113.200"), None, GOOD);
    assert_eq!(
        (r.status, json(&r)["error"].as_str()),
        (503, Some("busy")),
        "{r:?}"
    );
    assert!(r.h("retry-after").is_some());
    drop(held);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        post(s.port, Some("203.0.113.201"), None, GOOD).status,
        200,
        "the places are free again"
    );
}

#[test]
fn h12_the_global_and_daily_caps_answer_503_with_retry_after() {
    let s = start(&[("--global-per-min", "5"), ("--daily", "100000")]);
    for i in 0..5 {
        assert_eq!(
            post(s.port, Some(&format!("203.0.113.{}", i + 1)), None, GOOD).status,
            200,
            "request {i}"
        );
    }
    let r = post(s.port, Some("203.0.113.99"), None, GOOD);
    assert_eq!((r.status, json(&r)["error"].as_str()), (503, Some("busy")));
    let wait: u64 = r.h("retry-after").expect("Retry-After").parse().unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
    // the health check is not counted and not refused
    assert_eq!(get(s.port, "/healthz").status, 200);
    let s = start(&[("--daily", "3")]);
    for i in 0..3 {
        assert_eq!(
            post(s.port, Some(&format!("203.0.113.{}", i + 1)), None, GOOD).status,
            200
        );
    }
    let r = post(s.port, Some("203.0.113.9"), None, GOOD);
    assert_eq!(
        (r.status, json(&r)["error"].as_str()),
        (503, Some("daily_limit"))
    );
    let wait: u64 = r.h("retry-after").unwrap().parse().unwrap();
    assert!((1..=86_400).contains(&wait), "{wait}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expect = 86_400 - now % 86_400;
    assert!(
        wait.abs_diff(expect) <= 5,
        "Retry-After {wait} must be the seconds to the next UTC midnight ({expect})"
    );
}

#[test]
fn h13_cors_is_answered_for_exactly_one_origin_and_never_with_a_star() {
    let s = start(&[]);
    let pre = |origin: &str, method: &str, headers: &str| {
        send(s.port, format!("OPTIONS /try HTTP/1.1\r\nHost: x\r\nOrigin: {origin}\r\nAccess-Control-Request-Method: {method}\r\nAccess-Control-Request-Headers: {headers}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap()
    };
    let r = pre(ORIGIN, "POST", "content-type");
    assert_eq!(r.status, 204, "{r:?}");
    assert_eq!(r.h("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(r.h("access-control-allow-methods"), Some("POST"));
    assert_eq!(r.h("access-control-allow-headers"), Some("content-type"));
    assert!(r.h("access-control-allow-credentials").is_none());
    assert!(r
        .h("vary")
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("origin"));
    for (what, r) in [
        (
            "another origin",
            pre("https://evil.example.test", "POST", "content-type"),
        ),
        (
            "a prefix of the origin",
            pre("https://try.example.test.evil.test", "POST", "content-type"),
        ),
        ("a wrong method", pre(ORIGIN, "PUT", "content-type")),
        ("a wrong header", pre(ORIGIN, "POST", "authorization")),
    ] {
        assert!(
            r.h("access-control-allow-origin").is_none(),
            "{what}: {r:?}"
        );
        assert!(r.status == 403 || r.status == 204, "{what}: {r:?}");
        assert_ne!(r.h("access-control-allow-origin"), Some("*"));
    }
    // the real response carries the header only for the allowed origin
    let r = post(s.port, Some("203.0.113.31"), Some(ORIGIN), GOOD);
    assert_eq!(
        (r.status, r.h("access-control-allow-origin")),
        (200, Some(ORIGIN))
    );
    assert!(r.h("access-control-allow-credentials").is_none());
    let r = post(
        s.port,
        Some("203.0.113.32"),
        Some("https://evil.example.test"),
        GOOD,
    );
    assert_eq!(r.status, 200);
    assert!(r.h("access-control-allow-origin").is_none(), "{r:?}");
    let r = post(s.port, Some("203.0.113.33"), None, GOOD);
    assert!(r.h("access-control-allow-origin").is_none());
    // an error answer follows the same rule
    let r = post(s.port, Some("203.0.113.34"), Some(ORIGIN), "not json");
    assert_eq!(
        (r.status, r.h("access-control-allow-origin")),
        (400, Some(ORIGIN))
    );
}

#[test]
fn h14_nothing_from_a_request_reaches_stdout_or_stderr_over_1000_requests() {
    let s = start(&[("--global-per-min", "100000"), ("--daily", "1000000")]);
    // canaries and an address, built from parts at run time
    let canary_text = format!("CANARY-{}-{}", "TEXT", "7f3a9c");
    let canary_hdr = format!("CANARY-{}-{}", "HDR", "51d2e8");
    let canary_xff = format!("CANARY-{}-{}", "XFF", "0b6c44");
    let addr = format!("198.51.100.{}", 77);
    for i in 0..1000 {
        let kind = i % 8;
        let mut h = String::from("Host: x\r\nConnection: close\r\n");
        h += &format!("X-Canary: {canary_hdr}\r\nX-Forwarded-For: {canary_xff}, {addr}\r\n");
        let (ct, body): (&str, String) = match kind {
            0 => (
                "application/json",
                format!(r#"{{"text":"{canary_text}","tier":"T1"}}"#),
            ),
            1 => ("application/json", format!(r#"{{"text":"{canary_text}""#)), // truncated JSON
            2 => ("text/plain", canary_text.clone()),
            3 => (
                "application/json",
                format!(r#"{{"text":"{canary_text}","tier":"T9"}}"#),
            ),
            4 => (
                "application/json",
                format!(r#"{{"text":"{canary_text}","text":"b","tier":"T1"}}"#),
            ),
            5 => (
                "application/json",
                format!(r#"{{"text":"{canary_text}","tier":"T1","extra":1}}"#),
            ),
            6 => (
                "application/json",
                format!(r#"{{"text":"{}","tier":"T1"}}"#, canary_text.repeat(400)),
            ), // too large
            _ => ("application/json", format!("{canary_text}\u{0}")),
        };
        let req = format!(
            "POST /try HTTP/1.1\r\n{h}Content-Type: {ct}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let _ = send(s.port, req.as_bytes());
        if i % 100 == 0 {
            // a request line that is not HTTP at all
            let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
            let _ = c.write_all(format!("{canary_text} {canary_hdr}\r\n\r\n").as_bytes());
        }
    }
    std::thread::sleep(Duration::from_millis(1500));
    let (out, err) = (s.out.lock().unwrap().clone(), s.err.lock().unwrap().clone());
    for (name, text) in [("stdout", &out), ("stderr", &err)] {
        for (what, needle) in [
            ("text canary", &canary_text),
            ("header canary", &canary_hdr),
            ("forwarded-for canary", &canary_xff),
            ("address", &addr),
            ("loopback peer", &"127.0.0.1:".to_string()),
        ] {
            let t = if what == "loopback peer" {
                text.replace(&format!("listening 127.0.0.1:{}", s.port), "")
            } else {
                text.to_string()
            };
            assert!(
                !t.contains(needle.as_str()),
                "{name} contains the {what}: {t}"
            );
        }
    }
    assert!(
        err.trim().is_empty(),
        "stderr must stay empty while running: {err}"
    );
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines[0].starts_with("entropa-try-http listening "),
        "{lines:?}"
    );
    assert!(
        lines.len() >= 2,
        "at least one stats line after 1.5 s: {lines:?}"
    );
    for l in &lines[1..] {
        let ok = l.starts_with("stats ")
            && l[6..].split(' ').all(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or(("", ""));
                [
                    "200", "400", "404", "405", "408", "413", "415", "429", "503", "other",
                ]
                .contains(&k)
                    && v.parse::<u64>().is_ok()
            });
        assert!(
            ok,
            "only the start line and status counts are printed: {l:?}"
        );
    }
    // the counts add up to what was sent over the interval(s): at least 1,000 answers were counted
    let total: u64 = lines[1..]
        .iter()
        .flat_map(|l| l[6..].split(' '))
        .filter_map(|kv| kv.split_once('='))
        .filter_map(|(_, v)| v.parse::<u64>().ok())
        .sum();
    assert!(total >= 900, "the stats lines count the requests: {total}");
}

fn counts_by_key(out: &str) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::new();
    for l in out.lines().filter(|l| l.starts_with("stats ")) {
        for kv in l[6..].split(' ') {
            if let Some((k, v)) = kv.split_once('=') {
                *m.entry(k.to_string()).or_insert(0) += v.parse::<u64>().unwrap();
            }
        }
    }
    m
}

#[test]
fn h15_the_status_counts_are_filed_under_their_status_and_the_first_line_comes_after_one_interval()
{
    let s = start(&[("--stats-secs", "3")]);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        s.out.lock().unwrap().lines().count(),
        1,
        "only the start line before the first interval ends: {:?}",
        s.out.lock().unwrap()
    );
    for _ in 0..3 {
        assert_eq!(get(s.port, "/healthz").status, 200);
    }
    for _ in 0..2 {
        assert_eq!(get(s.port, "/nope").status, 404);
    }
    assert_eq!(get(s.port, "/try").status, 405);
    assert_eq!(
        send(
            s.port,
            b"DELETE /try HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap()
        .status,
        405
    );
    assert_eq!(send(s.port, b"POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 99999\r\nConnection: close\r\n\r\n").unwrap().status, 413);
    assert_eq!(post(s.port, Some("203.0.113.71"), None, GOOD).status, 200);
    let t = Instant::now();
    let m = loop {
        std::thread::sleep(Duration::from_millis(300));
        let m = counts_by_key(&s.out.lock().unwrap());
        if m.get("200") == Some(&4) || t.elapsed() > Duration::from_secs(9) {
            break m;
        }
    };
    let want: Vec<(&str, u64)> = vec![
        ("200", 4),
        ("400", 0),
        ("404", 2),
        ("405", 2),
        ("408", 0),
        ("413", 1),
        ("415", 0),
        ("429", 0),
        ("503", 0),
        ("other", 0),
    ];
    for (k, v) in want {
        assert_eq!(m.get(k), Some(&v), "status {k}: {m:?}");
    }
}

#[test]
fn h16_an_origin_with_a_host_is_accepted_and_a_body_of_exactly_the_read_limit_counts_for_its_client(
) {
    for origin in ["http://localhost:3000", "https://a", "http://a"] {
        let s = start(&[("--allow-origin", origin)]);
        assert_eq!(get(s.port, "/healthz").status, 200, "{origin}");
    }
    // a body of exactly 4,097 bytes (one over the handler's limit) reaches the handler, which answers 413 and counts the attempt against the client: the 11th is 429. Declared length:
    let s = start(&[]);
    let body = format!(r#"{{"text":"{}","tier":"T1"}}"#, "a".repeat(4097 - 23));
    assert_eq!(body.len(), 4097);
    for i in 0..10 {
        let r = post(s.port, Some("203.0.113.81"), None, &body);
        assert_eq!(r.status, 413, "request {i}: {r:?}");
    }
    assert_eq!(
        post(s.port, Some("203.0.113.81"), None, &body).status,
        429,
        "the 10 attempts were counted"
    );
    // and chunked
    let chunked = |xff: &str| {
        let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
        c.write_all(format!("POST /try HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nX-Forwarded-For: {xff}\r\nConnection: close\r\n\r\n1001\r\n{body}\r\n0\r\n\r\n").as_bytes()).unwrap();
        read_resp(&mut c, Duration::from_secs(5)).unwrap()
    };
    for i in 0..10 {
        let r = chunked("203.0.113.82");
        assert_eq!(r.status, 413, "chunked request {i}: {r:?}");
    }
    assert_eq!(chunked("203.0.113.82").status, 429);
}

#[test]
fn h17_every_start_has_its_own_salt_so_the_same_text_gives_a_different_record_hash() {
    // two servers, the same text in the same second: the signed subject hash covers the salted text hash, so it differs only because of the salt (a control: the same server twice gives the same hash)
    let (a, b) = (start(&[]), start(&[]));
    let body = r#"{"text":"the very same text","tier":"T1"}"#;
    let subject = |port: u16, who: &str| {
        let r = post(port, Some(who), None, body);
        assert_eq!(r.status, 200, "{r:?}");
        let ev =
            entropa_ledger::decode_event(json(&r)["record"]["event"].as_str().unwrap()).unwrap();
        (ev.fields.ts, ev.fields.subject_hash)
    };
    for attempt in 0..8 {
        let (x, y) = (
            subject(a.port, "203.0.113.91"),
            subject(b.port, "203.0.113.92"),
        );
        let x2 = subject(a.port, "203.0.113.93");
        if x.0 == y.0 && x.0 == x2.0 {
            assert_eq!(
                x.1, x2.1,
                "the same server gives the same hash for the same text in the same second"
            );
            assert_ne!(x.1, y.1, "two starts must not share a salt");
            return;
        }
        std::thread::sleep(Duration::from_millis(200 * (attempt + 1)));
    }
    panic!("the three requests never fell in one second");
}

#[test]
fn h18_an_http_11_request_without_exactly_one_host_header_is_refused_with_400_before_anything_else()
{
    // RFC 9112 section 3.2: a server MUST answer 400 to an HTTP/1.1 request that has no Host header or more than one. (LS3d found one answered 200.)
    let s = start(&[]);
    let valid = |hosts: &str| {
        format!(
            "POST /try HTTP/1.1\r\n{hosts}Content-Type: application/json\r\nContent-Length: {}\r\nX-Forwarded-For: 203.0.113.140\r\nConnection: close\r\n\r\n{GOOD}",
            GOOD.len()
        )
    };
    let bad: Vec<(&str, String)> = vec![
        ("healthz without Host", "GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n".into()),
        ("an unknown path without Host", "GET /nope HTTP/1.1\r\nConnection: close\r\n\r\n".into()),
        ("a valid gate request without Host", valid("")),
        ("a preflight without Host", format!("OPTIONS /try HTTP/1.1\r\nOrigin: {ORIGIN}\r\nAccess-Control-Request-Method: POST\r\nConnection: close\r\n\r\n")),
        ("two Host headers", "GET /healthz HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: close\r\n\r\n".into()),
        ("a valid gate request with two Host headers", valid("Host: a\r\nHost: b\r\n")),
    ];
    for (name, req) in &bad {
        let r = send(s.port, req.as_bytes()).unwrap_or_else(|| panic!("{name}: no answer"));
        assert_eq!(r.status, 400, "{name}: {r:?}");
        assert_eq!(json(&r)["error"], "bad_request", "{name}");
        assert!(r.h("access-control-allow-origin").is_none(), "{name}");
    }
    // the refused requests never reached the handler: they did not use up the client's allowance (ten valid requests of the same client still pass)
    for i in 0..10 {
        let r = send(s.port, valid("Host: x\r\n").as_bytes()).unwrap();
        assert_eq!(r.status, 200, "valid request {i}: {r:?}");
    }
    // exactly one Host works; HTTP/1.0 needs none
    assert_eq!(get(s.port, "/healthz").status, 200);
    assert_eq!(
        send(s.port, b"GET /healthz HTTP/1.0\r\n\r\n")
            .unwrap()
            .status,
        200
    );
    // the refusal is counted as a 400 in the status counts
    std::thread::sleep(Duration::from_millis(1500));
    let m = counts_by_key(&s.out.lock().unwrap());
    assert_eq!(m.get("400"), Some(&(bad.len() as u64)), "{m:?}");
}
