//! # entropa-explorer (stage S7e)
//!
//! The public explorer's read API as a pure library (`docs/ARCHITECTURE-EXPLORER.md` section 5): a
//! request value in, a response value out. It reads the static ledger bundle (verified on load) and
//! never writes anything; the HTTP binding, TLS and the cloud wiring come in later stages. The API is
//! GET only, takes no body, sets no cookie, needs no login, and applies a per-client rate limit with
//! an injected clock. The routes are in `api`, the limiter in `limiter`, the strict query parser in `query`.

mod api;
mod canon;
mod limiter;
mod query;

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Marker the S7d stubs used; kept so the red-stage tests still compile.
pub const NOT_IMPLEMENTED: &str = "not yet implemented";

/// Why an explorer could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplorerError {
    /// Reserved (the S7d stubs used it); never returned now.
    NotImplemented,
    /// The bundle is malformed or does not verify.
    Invalid(String),
}

/// A request as the transport adapter hands it over. `client` is the address the adapter itself
/// observed (never read from a header); header values are untrusted text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// HTTP method, upper case.
    pub method: String,
    /// The path, starting with `/`, without the query.
    pub path: String,
    /// The raw query string without the `?` (may be empty).
    pub query: String,
    /// The client address as seen by the adapter.
    pub client: String,
    /// Request headers (names lower case); never reflected, never trusted.
    pub headers: Vec<(String, String)>,
    /// Length of the request body in bytes (bodies are never read).
    pub body_len: usize,
}

/// A response: status, lower-case header names, and a canonical JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Header names (lower case) and values.
    pub headers: BTreeMap<String, String>,
    /// The body: canonical JSON (keys sorted, no whitespace); empty for 204.
    pub body: String,
}

/// The time source, injected so the rate limiter can be tested.
pub trait Clock {
    /// Seconds since the unix epoch.
    fn now_secs(&self) -> u64;
}

/// Limits of the read API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Sustained requests per minute per client (refill of one token every `60 / rate` seconds).
    pub rate_per_minute: u32,
    /// Burst size (bucket capacity).
    pub burst: u32,
    /// Largest response body in bytes.
    pub max_response_bytes: usize,
    /// Longest path in bytes.
    pub max_path_bytes: usize,
    /// Longest query string in bytes.
    pub max_query_bytes: usize,
    /// Largest page size.
    pub max_page: usize,
    /// Most clients the limiter remembers (the oldest are forgotten first).
    pub max_tracked_clients: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            rate_per_minute: 60,
            burst: 20,
            max_response_bytes: 256 * 1024,
            max_path_bytes: 256,
            max_query_bytes: 512,
            max_page: 100,
            max_tracked_clients: 10_000,
        }
    }
}

/// The read API over one verified bundle.
pub struct Explorer {
    data: api::Data,
    limits: Limits,
    limiter: Mutex<limiter::Limiter>,
}

impl Explorer {
    /// Load a bundle. It is verified with `entropa_ledger::verify_bundle` first; anything that does not
    /// verify is refused.
    pub fn from_bundle(bundle_json: &str, limits: Limits) -> Result<Explorer, ExplorerError> {
        entropa_ledger::verify_bundle(bundle_json)
            .map_err(|e| ExplorerError::Invalid(format!("{e:?}")))?;
        let v: serde_json::Value = serde_json::from_str(bundle_json)
            .map_err(|_| ExplorerError::Invalid("not valid JSON".into()))?;
        let data = api::Data::from_value(&v).map_err(ExplorerError::Invalid)?;
        let limiter = Mutex::new(limiter::Limiter::new(
            limits.rate_per_minute,
            limits.burst,
            limits.max_tracked_clients,
        ));
        Ok(Explorer {
            data,
            limits,
            limiter,
        })
    }

    /// Answer one request: rate limit, method, body, size caps, path shape, then the route.
    pub fn handle(&self, req: &Request, clock: &dyn Clock) -> Response {
        let taken = match self.limiter.lock() {
            Ok(mut l) => l.take(&req.client, clock.now_secs()),
            Err(_) => Err(1),
        };
        if let Err(wait) = taken {
            let mut r = finish(api::error(429, "rate_limited"));
            r.headers.insert("retry-after".into(), wait.to_string());
            return r;
        }
        if req.method == "OPTIONS" && req.body_len == 0 {
            return preflight();
        }
        if req.method != "GET" && req.method != "OPTIONS" {
            let mut r = finish(api::error(405, "method_not_allowed"));
            r.headers.insert("allow".into(), "GET, OPTIONS".into());
            return r;
        }
        if req.body_len > 0 {
            return finish(api::error(400, "bad_request"));
        }
        if req.path.len() > self.limits.max_path_bytes
            || req.query.len() > self.limits.max_query_bytes
        {
            return finish(api::error(414, "uri_too_long"));
        }
        let Some(rest) = req.path.strip_prefix("/api/") else {
            return finish(api::error(404, "not_found"));
        };
        if rest.is_empty() {
            return finish(api::error(404, "not_found"));
        }
        if !rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'/')
        {
            return finish(api::error(400, "bad_request"));
        }
        let segs: Vec<&str> = rest.split('/').collect();
        if segs.iter().any(|s| s.is_empty()) {
            return finish(api::error(400, "bad_request"));
        }
        let answer = api::route(&self.data, &self.limits, &segs, &req.query);
        if answer.status == 200 && answer.body.len() > self.limits.max_response_bytes {
            return finish(api::error(500, "response_too_large"));
        }
        finish(answer)
    }

    /// How many clients the rate limiter currently remembers.
    pub fn tracked_clients(&self) -> usize {
        self.limiter.lock().map_or(0, |l| l.tracked())
    }
}

/// Headers every response carries: CORS, content type, security headers.
fn base_headers() -> BTreeMap<String, String> {
    let mut h = BTreeMap::new();
    for (k, v) in [
        ("access-control-allow-origin", "*"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
        ("x-frame-options", "DENY"),
        (
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        ),
    ] {
        h.insert(k.to_string(), v.to_string());
    }
    h
}

fn finish(a: api::Answer) -> Response {
    let mut headers = base_headers();
    headers.insert(
        "content-type".into(),
        "application/json; charset=utf-8".into(),
    );
    let cache = match a.cache {
        // Only 200 answers carry a cache class (see `api::error`); everything else is never cached.
        Some(api::Cache::Immutable) => "public, max-age=31536000, immutable",
        Some(api::Cache::Short) => "public, max-age=15",
        None => "no-store",
    };
    headers.insert("cache-control".into(), cache.into());
    Response {
        status: a.status,
        headers,
        body: a.body,
    }
}

fn preflight() -> Response {
    let mut headers = base_headers();
    headers.insert("access-control-allow-methods".into(), "GET, OPTIONS".into());
    headers.insert("access-control-max-age".into(), "86400".into());
    headers.insert("cache-control".into(), "no-store".into());
    Response {
        status: 204,
        headers,
        body: String::new(),
    }
}
