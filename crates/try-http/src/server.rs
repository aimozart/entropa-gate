//! The server of `entropa-try-http` (a stage record (not published)): one route `POST /try` into `entropa_try::Service::handle`, `GET /healthz`, everything else 404/405. No decision logic here.
use crate::settings::Settings;
use crate::{client_key, Caps};
use bytes::Bytes;
use entropa_core::Probe;
use entropa_try::{Config, HttpRequest, Service};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Instant};

const HEADER_TIMEOUT: Duration = Duration::from_secs(2);
const BODY_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER_BYTES: usize = 8192;
const MAX_HEADERS: usize = 64;
/// The library accepts 4,096 bytes; one more is read so that "too large" is seen, never more.
const BODY_READ_LIMIT: usize = 4097;
const STATUS_KEYS: [u16; 9] = [200, 400, 404, 405, 408, 413, 415, 429, 503];

struct Shared {
    svc: Service,
    caps: Mutex<Caps>,
    permits: Arc<Semaphore>,
    hops: usize,
    origin: String,
    counts: [AtomicU64; 10],
}

impl Shared {
    fn count(&self, status: u16) {
        let i = STATUS_KEYS.iter().position(|k| *k == status).unwrap_or(9);
        self.counts[i].fetch_add(1, Ordering::Relaxed);
    }
    /// One line of status counts for the interval since the last call (no request text, no address).
    fn stats_line(&self) -> String {
        let mut s = String::from("stats");
        for (i, k) in STATUS_KEYS.iter().enumerate() {
            s += &format!(" {k}={}", self.counts[i].swap(0, Ordering::Relaxed));
        }
        s + &format!(" other={}", self.counts[9].swap(0, Ordering::Relaxed))
    }
}

type Resp = Response<Full<Bytes>>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn reply(
    status: u16,
    body: String,
    retry_after: Option<u64>,
    cors: Option<&str>,
    on_try: bool,
) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(body.clone())));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let h = r.headers_mut();
    h.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    h.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        HeaderName::from_static("connection"),
        HeaderValue::from_static("close"),
    );
    if !body.is_empty() {
        h.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
    }
    if let Some(s) = retry_after {
        if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
            h.insert(HeaderName::from_static("retry-after"), v);
        }
    }
    if on_try {
        h.insert(
            HeaderName::from_static("vary"),
            HeaderValue::from_static("Origin"),
        );
    }
    if let Some(o) = cors {
        if let Ok(v) = HeaderValue::from_str(o) {
            h.insert(HeaderName::from_static("access-control-allow-origin"), v);
        }
    }
    r
}
fn empty(status: u16) -> Resp {
    reply(status, String::new(), None, None, false)
}
fn error(status: u16, code: &str, retry_after: Option<u64>, cors: Option<&str>) -> Resp {
    reply(
        status,
        format!("{{\"error\":\"{code}\"}}"),
        retry_after,
        cors,
        true,
    )
}

fn header<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

fn preflight(req: &Request<Incoming>, sh: &Shared) -> Resp {
    let origin_ok = header(req, "origin") == Some(sh.origin.as_str());
    let method_ok = header(req, "access-control-request-method") == Some("POST");
    let headers_ok = header(req, "access-control-request-headers").is_none_or(|h| {
        h.split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .all(|t| t.is_empty() || t == "content-type")
    });
    if !(origin_ok && method_ok && headers_ok) {
        return empty(403);
    }
    let mut r = reply(204, String::new(), None, Some(&sh.origin), true);
    let h = r.headers_mut();
    h.insert(
        HeaderName::from_static("access-control-allow-methods"),
        HeaderValue::from_static("POST"),
    );
    h.insert(
        HeaderName::from_static("access-control-allow-headers"),
        HeaderValue::from_static("content-type"),
    );
    h.insert(
        HeaderName::from_static("access-control-max-age"),
        HeaderValue::from_static("600"),
    );
    r
}

async fn post_try(req: Request<Incoming>, peer: IpAddr, sh: &Shared) -> Resp {
    let cors = header(&req, "origin")
        .filter(|o| *o == sh.origin)
        .map(str::to_string);
    let cors = cors.as_deref();
    let verdict = sh.caps.lock().map_or(Ok(()), |mut c| c.admit(now_secs()));
    if let Err(c) = verdict {
        return error(503, c.code, Some(c.retry_after), cors);
    }
    let Ok(_permit) = sh.permits.clone().try_acquire_owned() else {
        return error(503, "busy", Some(1), cors);
    };
    if let Some(len) = header(&req, "content-length").and_then(|v| v.parse::<u64>().ok()) {
        if len > BODY_READ_LIMIT as u64 {
            return error(413, "too_large", None, cors);
        }
    }
    let content_type = header(&req, "content-type").unwrap_or("").to_string();
    let forwarded: Vec<&str> = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let joined = forwarded.join(",");
    let key = client_key(
        if forwarded.is_empty() {
            None
        } else {
            Some(joined.as_str())
        },
        sh.hops,
        peer,
    );
    let mut body = req.into_body();
    let mut buf: Vec<u8> = Vec::new();
    let deadline = Instant::now() + BODY_TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match timeout(left, body.frame()).await {
            Err(_) => return error(408, "timeout", None, cors),
            Ok(None) => break,
            Ok(Some(Err(_))) => return error(400, "not_json", None, cors),
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    buf.extend_from_slice(&data);
                    if buf.len() > BODY_READ_LIMIT {
                        return error(413, "too_large", None, cors);
                    }
                }
            }
        }
    }
    let out = sh.svc.handle(
        &HttpRequest {
            content_type: &content_type,
            client: &key,
            body: &buf,
        },
        now_secs(),
    );
    reply(out.status, out.body, out.retry_after_secs, cors, true)
}

async fn route(req: Request<Incoming>, peer: IpAddr, sh: &Shared) -> Resp {
    match (req.method().clone(), req.uri().path()) {
        (Method::GET, "/healthz") => empty(200),
        (_, "/healthz") => empty(405),
        (Method::POST, "/try") => post_try(req, peer, sh).await,
        (Method::OPTIONS, "/try") => preflight(&req, sh),
        (_, "/try") => empty(405),
        _ => empty(404),
    }
}

async fn handle(req: Request<Incoming>, peer: IpAddr, sh: Arc<Shared>) -> Result<Resp, Infallible> {
    // RFC 9112 section 3.2: an HTTP/1.1 request with no Host header, or with more than one, is answered 400 before anything else (LS3b2)
    let r = if req.version() == hyper::Version::HTTP_11
        && req.headers().get_all("host").iter().count() != 1
    {
        error(400, "bad_request", None, None)
    } else {
        match timeout(REQUEST_TIMEOUT, route(req, peer, &sh)).await {
            Ok(r) => r,
            Err(_) => error(408, "timeout", None, None),
        }
    };
    sh.count(r.status().as_u16());
    Ok(r)
}

async fn serve(stream: TcpStream, sh: Arc<Shared>) {
    let Ok(peer) = stream.peer_addr() else { return };
    let ip = peer.ip();
    let service = service_fn(move |req| handle(req, ip, sh.clone()));
    let mut b = http1::Builder::new();
    b.timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(MAX_HEADER_BYTES)
        .max_headers(MAX_HEADERS)
        .keep_alive(false);
    let _ = b.serve_connection(TokioIo::new(stream), service).await;
}

fn line(text: &str) {
    let mut o = std::io::stdout();
    let _ = writeln!(o, "{text}");
    let _ = o.flush();
}

/// Run the server until the process is stopped. Errors are start-up errors (no request text is ever in them).
pub async fn run(s: Settings) -> Result<(), String> {
    let mut salt = vec![0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut salt))
        .map_err(|_| "cannot read random bytes for the salt".to_string())?;
    HeaderValue::from_str(&s.allow_origin)
        .map_err(|_| "--allow-origin is not a valid header value".to_string())?;
    let svc = Service::new(
        Probe::spawn(),
        Config {
            salt,
            ..Config::default()
        },
    );
    let shared = Arc::new(Shared {
        svc,
        caps: Mutex::new(Caps::new(s.global_per_min, s.daily)),
        permits: Arc::new(Semaphore::new(s.concurrency)),
        hops: s.trusted_hops,
        origin: s.allow_origin.clone(),
        counts: Default::default(),
    });
    let listener = TcpListener::bind(s.listen)
        .await
        .map_err(|e| format!("cannot listen: {}", e.kind()))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    line(&format!(
        "entropa-try-http listening {addr} trusted_hops={}",
        s.trusted_hops
    ));
    let sh = shared.clone();
    let every = Duration::from_secs(s.stats_secs);
    tokio::spawn(async move {
        let mut t = tokio::time::interval_at(Instant::now() + every, every);
        loop {
            t.tick().await;
            line(&sh.stats_line());
        }
    });
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(serve(stream, shared.clone()));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}
