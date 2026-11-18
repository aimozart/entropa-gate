#![no_main]
use entropa_explorer::{Clock, Explorer, Limits, Request};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

struct At(u64);
impl Clock for At {
    fn now_secs(&self) -> u64 {
        self.0
    }
}

const BUNDLE: &str = include_str!("../../tests/golden/bundle_seed1_n5.json");

// The router and the strict query parser never panic on any method, path or query; every answer is one of
// the documented statuses with a JSON body (empty only for 204), no header value carries a line break, and
// every error body is one of a fixed set, so nothing sent by the client can be echoed.
fuzz_target!(|data: &[u8]| {
    static E: OnceLock<Explorer> = OnceLock::new();
    static N: AtomicUsize = AtomicUsize::new(0);
    let e = E.get_or_init(|| Explorer::from_bundle(BUNDLE, Limits::default()).unwrap());
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (first, rest) = text.split_once('\n').unwrap_or((text, ""));
    let (method, path) = match first.split_once(' ') {
        Some((m, p)) if m.len() < 8 => (m, p),
        _ => ("GET", first),
    };
    let (query, body) = rest.split_once('\n').unwrap_or((rest, ""));
    let req = Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        client: format!("fuzz-{}", N.fetch_add(1, Ordering::Relaxed)),
        headers: vec![("x-forwarded-for".into(), body.to_string())],
        body_len: body.len(),
    };
    let r = e.handle(&req, &At(1_800_000_000));
    assert!(matches!(r.status, 200 | 204 | 400 | 404 | 405 | 414 | 429 | 500), "status {}", r.status);
    if r.status == 204 {
        assert!(r.body.is_empty());
    } else {
        assert!(r.body.starts_with('{') && r.body.ends_with('}'));
    }
    for (k, v) in &r.headers {
        assert!(!k.contains(['\r', '\n']) && !v.contains(['\r', '\n']));
    }
    if r.status >= 400 {
        // Error bodies are one of a fixed set, so nothing the client sent can come back.
        let fixed = ["bad_request", "not_found", "method_not_allowed", "rate_limited", "uri_too_long", "response_too_large"];
        assert!(fixed.iter().any(|c| r.body == format!("{{\"error\":\"{c}\"}}")), "{}", r.body);
    }
});
