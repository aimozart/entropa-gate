//! Executing one scenario against a fresh server (a process or a container): the steps, the three pass conditions and the closed failure reasons (a stage record (not published)).
use super::schema::{bytes_of, unescape, Expect, Scenario, Server, Step};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Where the server under test comes from.
#[derive(Clone)]
pub enum Target {
    /// A program path.
    Binary(String),
    /// A local image name.
    Container(String),
}

/// How one scenario ended.
pub struct Outcome {
    /// The closed failure reason, or `None` when the scenario passed.
    pub reason: Option<&'static str>,
    /// Whether the failed step was marked as an attack.
    pub accepted_attack: bool,
}

const START_LINE: &str = "entropa-try-http listening ";
const STATS_KEYS: [&str; 10] = [
    "200", "400", "404", "405", "408", "413", "415", "429", "503", "other",
];

struct Deadline(Instant);
impl Deadline {
    fn left(&self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }
    fn over(&self) -> bool {
        Instant::now() >= self.0
    }
    fn cap(&self, d: Duration) -> Duration {
        d.min(self.left()).max(Duration::from_millis(1))
    }
}

// ---------------- the server under test ----------------
struct Srv {
    port: u16,
    proc: Option<Child>,
    container: Option<String>,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}

fn command_timeout(args: &[&str], limit: Duration) -> Option<(bool, String, String)> {
    let mut c = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let (mut o, mut e) = (c.stdout.take()?, c.stderr.take()?);
    let ho = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = o.read_to_string(&mut s);
        s
    });
    let he = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = e.read_to_string(&mut s);
        s
    });
    let t = Instant::now();
    let status = loop {
        match c.try_wait() {
            Ok(Some(s)) => break Some(s.success()),
            Ok(None) if t.elapsed() < limit => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = c.kill();
                let _ = c.wait();
                break None;
            }
        }
    };
    let (so, se) = (ho.join().unwrap_or_default(), he.join().unwrap_or_default());
    status.map(|ok| (ok, so, se))
}

fn pipe(r: impl Read + Send + 'static, sink: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut r = r;
        let mut b = [0u8; 4096];
        while let Ok(n) = r.read(&mut b) {
            if n == 0 {
                break;
            }
            if let Ok(mut s) = sink.lock() {
                s.push_str(&String::from_utf8_lossy(&b[..n]));
            }
        }
    });
}

fn settings(cfg: &Server) -> Vec<String> {
    let mut a = vec![
        "--trusted-hops".to_string(),
        cfg.trusted_hops.unwrap_or(1).to_string(),
        "--allow-origin".into(),
        cfg.allow_origin
            .clone()
            .unwrap_or_else(|| "https://try.example.test".into()),
        "--stats-secs".into(),
        cfg.stats_secs.unwrap_or(1).to_string(),
    ];
    for (flag, v) in [
        ("--global-per-min", cfg.global_per_min.map(u64::from)),
        ("--daily", cfg.daily.map(u64::from)),
        ("--concurrency", cfg.concurrency.map(|c| c as u64)),
    ] {
        if let Some(v) = v {
            a.push(flag.into());
            a.push(v.to_string());
        }
    }
    a
}

fn port_of(line: &str) -> Option<u16> {
    line.split_whitespace()
        .nth(2)?
        .rsplit(':')
        .next()?
        .parse()
        .ok()
}

fn start(target: &Target, cfg: &Server, name: &str) -> Result<Srv, &'static str> {
    let (out, err) = (
        Arc::new(Mutex::new(String::new())),
        Arc::new(Mutex::new(String::new())),
    );
    match target {
        Target::Binary(path) => {
            let mut child = Command::new(path)
                .args(["--listen", "127.0.0.1:0"])
                .args(settings(cfg))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| "runner_error")?;
            if let (Some(o), Some(e)) = (child.stdout.take(), child.stderr.take()) {
                pipe(o, out.clone());
                pipe(e, err.clone());
            }
            let t = Instant::now();
            loop {
                let line = out.lock().ok().and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with(START_LINE))
                        .map(str::to_string)
                });
                if let Some(p) = line.as_deref().and_then(port_of) {
                    return Ok(Srv {
                        port: p,
                        proc: Some(child),
                        container: None,
                        out,
                        err,
                    });
                }
                if t.elapsed() > Duration::from_secs(5) || matches!(child.try_wait(), Ok(Some(_))) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("no_start_line");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Target::Container(image) => {
            let mut args: Vec<String> = [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--memory",
                "128m",
                "--memory-swap",
                "128m",
                "--pids-limit",
                "64",
                "-p",
                "127.0.0.1::8080",
                image,
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            args.extend(settings(cfg));
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            match command_timeout(&a, Duration::from_secs(30)) {
                Some((true, _, _)) => {}
                _ => return Err("runner_error"),
            }
            let srv = Srv {
                port: 0,
                proc: None,
                container: Some(name.to_string()),
                out,
                err,
            };
            let t = Instant::now();
            loop {
                let mapped = command_timeout(
                    &["docker", "port", name, "8080/tcp"],
                    Duration::from_secs(10),
                )
                .filter(|r| r.0)
                .and_then(|r| {
                    r.1.lines().next().and_then(|l| {
                        l.rsplit(':')
                            .next()
                            .and_then(|p| p.trim().parse::<u16>().ok())
                    })
                });
                let (o, _) = logs(&srv);
                if let (Some(p), true) = (mapped, o.lines().any(|l| l.starts_with(START_LINE))) {
                    let mut srv = srv;
                    srv.port = p;
                    return Ok(srv);
                }
                if t.elapsed() > Duration::from_secs(10) {
                    stop(srv);
                    return Err("no_start_line");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// The captured stdout and stderr so far.
fn logs(s: &Srv) -> (String, String) {
    match &s.container {
        Some(n) => command_timeout(&["docker", "logs", n], Duration::from_secs(10))
            .map(|(_, o, e)| (o, e))
            .unwrap_or_default(),
        None => (
            s.out.lock().map(|g| g.clone()).unwrap_or_default(),
            s.err.lock().map(|g| g.clone()).unwrap_or_default(),
        ),
    }
}

impl Drop for Srv {
    fn drop(&mut self) {
        if let Some(mut c) = self.proc.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(n) = self.container.take() {
            let _ = command_timeout(&["docker", "stop", "-t", "2", &n], Duration::from_secs(20));
            // stopped, never removed
        }
    }
}

fn stop(s: Srv) {
    drop(s);
}

// ---------------- HTTP over a raw socket ----------------
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
enum Got {
    Resp(Resp),
    Closed,
    Timeout,
}

fn connect(port: u16, d: &Deadline) -> Option<TcpStream> {
    let a = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&a, d.cap(Duration::from_secs(3))).ok()
}

fn send_all(s: &mut TcpStream, b: &[u8], d: &Deadline) -> bool {
    let _ = s.set_write_timeout(Some(d.cap(Duration::from_secs(5))));
    s.write_all(b).is_ok()
}

fn parse_head(buf: &[u8]) -> Option<(Resp, usize)> {
    let i = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..i]).into_owned();
    let mut lines = head.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Some((
        Resp {
            status,
            headers,
            body: vec![],
        },
        i + 4,
    ))
}

fn read_resp(s: &mut TcpStream, within: Duration, d: &Deadline) -> Got {
    let t = Instant::now();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut quiet_since = Instant::now();
    loop {
        if t.elapsed() >= within || d.over() {
            return match parse_head(&buf) {
                Some((mut r, at)) => {
                    r.body = buf[at..].to_vec();
                    Got::Resp(r)
                }
                None => Got::Timeout,
            };
        }
        let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
        let n = match s.read(&mut chunk) {
            Ok(0) => {
                return match parse_head(&buf) {
                    Some((mut r, at)) => {
                        r.body = buf[at..].to_vec();
                        Got::Resp(r)
                    }
                    None => Got::Closed,
                };
            }
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                0
            }
            Err(_) => {
                return match parse_head(&buf) {
                    Some((mut r, at)) => {
                        r.body = buf[at..].to_vec();
                        Got::Resp(r)
                    }
                    None => Got::Closed,
                };
            }
        };
        if n > 0 {
            buf.extend_from_slice(&chunk[..n]);
            quiet_since = Instant::now();
        }
        if let Some((mut r, at)) = parse_head(&buf) {
            let len = r
                .headers
                .iter()
                .find(|(k, _)| k == "content-length")
                .and_then(|(_, v)| v.parse::<usize>().ok());
            let have = buf.len() - at;
            let done = match len {
                Some(l) => have >= l,
                None => quiet_since.elapsed() > Duration::from_millis(300),
            };
            if done {
                r.body = buf[at..at + len.unwrap_or(have).min(have)].to_vec();
                return Got::Resp(r);
            }
        }
    }
}

fn check(e: &Expect, got: &Got) -> Result<(), &'static str> {
    match got {
        Got::Timeout => Err("timeout"),
        Got::Closed => {
            if e.or_close
                || (e.statuses.is_none()
                    && e.headers_present.is_empty()
                    && e.header_equals.is_empty()
                    && e.body_equals.is_none()
                    && e.body_json_equals.is_none())
            {
                Ok(())
            } else {
                Err("expect_status")
            }
        }
        Got::Resp(r) => {
            match &e.statuses {
                Some(st) if !st.contains(&r.status) => return Err("expect_status"),
                None if e.or_close => return Err("expect_status"),
                _ => {}
            }
            let h = |n: &str| {
                r.headers
                    .iter()
                    .find(|(k, _)| k == &n.to_ascii_lowercase())
                    .map(|(_, v)| v.as_str())
            };
            if e.headers_present.iter().any(|n| h(n).is_none())
                || e.headers_absent.iter().any(|n| h(n).is_some())
                || e.header_equals
                    .iter()
                    .any(|(n, v)| h(n) != Some(v.as_str()))
            {
                return Err("expect_header");
            }
            let body = String::from_utf8_lossy(&r.body);
            if let Some(b) = &e.body_equals {
                if body != b.as_str() {
                    return Err("expect_body");
                }
            }
            if let Some(j) = &e.body_json_equals {
                if serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .as_ref()
                    != Some(j)
                {
                    return Err("expect_body");
                }
            }
            Ok(())
        }
    }
}

// ---------------- steps ----------------
struct Run<'a> {
    port: u16,
    d: Deadline,
    conns: BTreeMap<String, TcpStream>,
    expire: Vec<(String, Instant)>,
    escapes: bool,
    srv: &'a Srv,
}
impl Run<'_> {
    /// Close the held connections whose time is up.
    fn expire_due(&mut self) {
        let now = Instant::now();
        let due: Vec<String> = self
            .expire
            .iter()
            .filter(|(_, t)| *t <= now)
            .map(|(c, _)| c.clone())
            .collect();
        for c in due {
            self.conns.remove(&c);
        }
        self.expire.retain(|(_, t)| *t > now);
    }
    /// Sleep `ms`, closing held connections on time; false when the scenario deadline passes.
    fn nap(&mut self, ms: u64) -> bool {
        let end = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < end {
            if self.d.over() {
                return false;
            }
            self.expire_due();
            std::thread::sleep(
                Duration::from_millis(25).min(end.saturating_duration_since(Instant::now())),
            );
        }
        self.expire_due();
        !self.d.over()
    }
}
type StepResult = Result<(), (&'static str, bool)>;

fn ranges_ok(
    counts: &BTreeMap<String, u64>,
    want: &BTreeMap<String, (u64, u64)>,
    other_applies: bool,
) -> bool {
    let named: Vec<&String> = want.keys().filter(|k| k.as_str() != "other").collect();
    let mut other = 0u64;
    for (k, v) in counts {
        if named.contains(&k) {
            continue;
        }
        if k == "closed" || !other_applies || want.contains_key("other") {
            if k == "closed" {
                if *v > 0 {
                    return false;
                }
            } else {
                other += v;
            }
        } else if *v > 0 {
            return false;
        }
    }
    let in_range = |v: u64, (lo, hi): (u64, u64)| v >= lo && v <= hi;
    want.iter().all(|(k, r)| {
        if k == "other" {
            in_range(other, *r)
        } else {
            in_range(counts.get(k).copied().unwrap_or(0), *r)
        }
    })
}

fn burst(
    run: &Run,
    count: u64,
    parallel: u64,
    template: &str,
    within_ms: u64,
) -> Result<BTreeMap<String, u64>, &'static str> {
    let next = AtomicU64::new(0);
    let done = AtomicU64::new(0);
    let hist: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
    let limit = Deadline(Instant::now() + Duration::from_millis(within_ms).min(run.d.left()));
    std::thread::scope(|sc| {
        for _ in 0..parallel {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= count || limit.over() {
                    break;
                }
                let filled = template.replace("{i}", &i.to_string());
                let bytes = if run.escapes {
                    unescape(&filled)
                } else {
                    filled.into_bytes()
                };
                let key = match connect(run.port, &limit) {
                    Some(mut s) => {
                        if send_all(&mut s, &bytes, &limit) {
                            match read_resp(&mut s, limit.cap(Duration::from_secs(8)), &limit) {
                                Got::Resp(r) => r.status.to_string(),
                                _ => "closed".to_string(),
                            }
                        } else {
                            "closed".to_string()
                        }
                    }
                    None => "closed".to_string(),
                };
                if let Ok(mut h) = hist.lock() {
                    *h.entry(key).or_insert(0) += 1;
                }
                done.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    if done.load(Ordering::SeqCst) < count {
        return Err("timeout");
    }
    Ok(hist.into_inner().unwrap_or_default())
}

fn totals(out: &str) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for l in out.lines().filter(|l| l.starts_with("stats ")) {
        for kv in l[6..].split(' ') {
            if let Some((k, v)) = kv.split_once('=') {
                *m.entry(k.to_string()).or_insert(0) += v.parse::<u64>().unwrap_or(0);
            }
        }
    }
    m
}

fn step(run: &mut Run, st: &Step) -> StepResult {
    let bad = |e: &'static str, attack: &Option<bool>| (e, attack.unwrap_or(false));
    match st {
        Step::Open { conn } => {
            let s = connect(run.port, &run.d).ok_or(("runner_error", false))?;
            run.conns.insert(conn.clone(), s);
        }
        Step::Send {
            conn,
            text,
            hex,
            repeat,
            piece,
            gap_ms,
            pause_ms,
        } => {
            let b =
                bytes_of(text, hex, *repeat, run.escapes).map_err(|_| ("runner_error", false))?;
            if !run.conns.contains_key(conn) {
                let s = connect(run.port, &run.d).ok_or(("runner_error", false))?;
                run.conns.insert(conn.clone(), s);
            }
            let mut s = run.conns.remove(conn).ok_or(("runner_error", false))?;
            match piece {
                Some(p) => {
                    for c in b.chunks(*p) {
                        if !send_all(&mut s, c, &run.d) {
                            break;
                        }
                        if !run.nap(gap_ms.unwrap_or(0)) {
                            return Err(("timeout", false));
                        }
                    }
                }
                None => {
                    let _ = send_all(&mut s, &b, &run.d);
                }
            }
            run.conns.insert(conn.clone(), s);
            if !run.nap(pause_ms.unwrap_or(0)) {
                return Err(("timeout", false));
            }
        }
        Step::Hold {
            conn,
            text,
            hex,
            repeat,
            for_ms,
        } => {
            let b =
                bytes_of(text, hex, *repeat, run.escapes).map_err(|_| ("runner_error", false))?;
            let mut s = connect(run.port, &run.d).ok_or(("runner_error", false))?;
            let _ = send_all(&mut s, &b, &run.d);
            run.conns.insert(conn.clone(), s);
            if let Some(ms) = for_ms {
                run.expire
                    .push((conn.clone(), Instant::now() + Duration::from_millis(*ms)));
            }
        }
        Step::Release { conn } => {
            run.conns.remove(conn);
        }
        Step::Read {
            conn,
            within_ms,
            expect,
            attack,
        } => {
            let s = run.conns.get_mut(conn).ok_or(("runner_error", false))?;
            let got = read_resp(
                s,
                run.d.cap(Duration::from_millis(within_ms.unwrap_or(3000))),
                &run.d,
            );
            if let Some(e) = expect {
                check(e, &got).map_err(|r| bad(r, attack))?;
            }
        }
        Step::Request {
            text,
            hex,
            repeat,
            within_ms,
            expect,
            attack,
        } => {
            let b =
                bytes_of(text, hex, *repeat, run.escapes).map_err(|_| ("runner_error", false))?;
            let mut s = connect(run.port, &run.d).ok_or(("runner_error", false))?;
            let got = if send_all(&mut s, &b, &run.d) {
                read_resp(
                    &mut s,
                    run.d.cap(Duration::from_millis(within_ms.unwrap_or(3000))),
                    &run.d,
                )
            } else {
                Got::Closed
            };
            if let Some(e) = expect {
                check(e, &got).map_err(|r| bad(r, attack))?;
            }
        }
        Step::Burst {
            count,
            parallel,
            template,
            within_ms,
            expect_counts,
            attack,
        } => {
            let hist =
                burst(run, *count, *parallel, template, *within_ms).map_err(|r| bad(r, attack))?;
            if !ranges_ok(&hist, expect_counts, true) {
                return Err(bad("expect_counts", attack));
            }
        }
        Step::Sleep { ms } => {
            if !run.nap(*ms) {
                return Err(("timeout", false));
            }
        }
        Step::Stats {
            wait_ms,
            expect_totals,
            attack,
        } => {
            if !run.nap(*wait_ms) {
                return Err(("timeout", false));
            }
            let t = totals(&logs(run.srv).0);
            if expect_totals.iter().any(|(k, (lo, hi))| {
                t.get(k).copied().unwrap_or(0) < *lo || t.get(k).copied().unwrap_or(0) > *hi
            }) {
                return Err(bad("expect_counts", attack));
            }
        }
    }
    Ok(())
}

fn stdout_ok(out: &str) -> bool {
    let mut lines = out.lines();
    if !lines.next().is_some_and(|l| l.starts_with(START_LINE)) {
        return false;
    }
    lines.all(|l| {
        l.strip_prefix("stats ").is_some_and(|rest| {
            rest.split(' ').all(|kv| {
                kv.split_once('=')
                    .is_some_and(|(k, v)| STATS_KEYS.contains(&k) && v.parse::<u64>().is_ok())
            })
        })
    })
}

/// Run one scenario against a fresh server. `name` is unique per scenario (container name).
pub fn run_scenario(sc: &Scenario, target: &Target, name: &str, escapes: bool) -> Outcome {
    // a scenario marked `attack` counts any unmet EXPECTATION as an accepted attack (a timeout or a runner problem is not an expectation)
    let fail = |reason: &'static str, attack: bool| Outcome {
        reason: Some(reason),
        accepted_attack: attack || (sc.attack == Some(true) && reason.starts_with("expect_")),
    };
    let cfg = sc.server.clone().unwrap_or(Server {
        trusted_hops: None,
        allow_origin: None,
        global_per_min: None,
        daily: None,
        concurrency: None,
        stats_secs: None,
    });
    let srv = match start(target, &cfg, name) {
        Ok(s) => s,
        Err(r) => return fail(r, false),
    };
    let d = Deadline(Instant::now() + Duration::from_millis(sc.timeout_ms.unwrap_or(60_000)));
    let mut run = Run {
        port: srv.port,
        d,
        conns: BTreeMap::new(),
        expire: Vec::new(),
        escapes,
        srv: &srv,
    };
    let mut result: StepResult = Ok(());
    for st in &sc.steps {
        run.expire_due();
        if run.d.over() {
            result = Err(("timeout", false));
        } else {
            result = step(&mut run, st);
        }
        if result.is_err() {
            break;
        }
    }
    let outcome = match result {
        Err((r, a)) => fail(r, a),
        Ok(()) => {
            let alive_deadline = Deadline(Instant::now() + Duration::from_secs(5));
            run.conns.clear();
            let alive = sc.final_alive == Some(false)
                || connect(srv.port, &alive_deadline).is_some_and(|mut s| {
                    send_all(&mut s, b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", &alive_deadline) && matches!(read_resp(&mut s, Duration::from_secs(3), &alive_deadline), Got::Resp(r) if r.status == 200)
                });
            if !alive {
                fail("not_alive", false)
            } else {
                std::thread::sleep(Duration::from_millis(1500));
                let (out, err) = logs(&srv);
                if sc.secrets.iter().any(|s| {
                    !s.is_empty() && (out.contains(s.as_str()) || err.contains(s.as_str()))
                }) {
                    fail("leak", false)
                } else if !err.trim().is_empty() {
                    fail("stderr_not_empty", false)
                } else if !stdout_ok(&out) {
                    fail("bad_stdout_line", false)
                } else {
                    Outcome {
                        reason: None,
                        accepted_attack: false,
                    }
                }
            }
        }
    };
    drop(run);
    stop(srv);
    outcome
}
