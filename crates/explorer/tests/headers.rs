//! CORS, cache and static security headers; no cookies, no auth, no storage writes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

fn h<'a>(r: &'a Response, k: &str) -> Option<&'a str> {
    r.headers.get(k).map(String::as_str)
}

const SAMPLE: [&str; 9] = [
    "/api/healthz",
    "/api/head",
    "/api/records",
    "/api/records/3",
    "/api/receipts/3",
    "/api/actors",
    "/api/nothing",
    "/api/records?limit=0",
    "/api/consistency?old=9&new=25",
];

#[test]
fn h1_every_response_carries_the_same_static_security_headers() {
    let e = explorer();
    for t in SAMPLE {
        let r = ask(&e, t);
        assert_eq!(h(&r, "access-control-allow-origin"), Some("*"), "{t}");
        assert_eq!(
            h(&r, "content-type"),
            Some("application/json; charset=utf-8"),
            "{t}"
        );
        assert_eq!(h(&r, "x-content-type-options"), Some("nosniff"), "{t}");
        assert_eq!(h(&r, "referrer-policy"), Some("no-referrer"), "{t}");
        assert_eq!(
            h(&r, "content-security-policy"),
            Some("default-src 'none'; frame-ancestors 'none'"),
            "{t}"
        );
        assert_eq!(h(&r, "x-frame-options"), Some("DENY"), "{t}");
        assert!(
            h(&r, "strict-transport-security").is_some_and(|v| v.contains("max-age=")),
            "{t}"
        );
    }
}

#[test]
fn h2_no_cookies_no_auth_challenges_no_credentials() {
    let e = explorer();
    for t in SAMPLE {
        let r = ask(&e, t);
        for k in r.headers.keys() {
            assert!(
                !k.contains("cookie") && k != "www-authenticate" && k != "authorization",
                "{t}: {k}"
            );
        }
        assert_ne!(
            h(&r, "access-control-allow-credentials"),
            Some("true"),
            "{t}"
        );
    }
}

#[test]
fn h3_cache_classes() {
    let e = explorer();
    let immutable = "public, max-age=31536000, immutable";
    for t in [
        "/api/records/3",
        "/api/receipts/3",
        "/api/consistency?old=9&new=25",
    ] {
        assert_eq!(h(&ask(&e, t), "cache-control"), Some(immutable), "{t}");
    }
    for t in [
        "/api/head",
        "/api/records",
        "/api/checkpoints",
        "/api/actors",
        "/api/feeds/entropa",
        "/api/witnesses",
    ] {
        assert_eq!(
            h(&ask(&e, t), "cache-control"),
            Some("public, max-age=15"),
            "{t}"
        );
    }
    for t in ["/api/healthz", "/api/nothing", "/api/records?limit=0"] {
        assert_eq!(h(&ask(&e, t), "cache-control"), Some("no-store"), "{t}");
    }
}

#[test]
fn h4_the_preflight_answers_with_methods_and_no_credentials() {
    let e = explorer();
    let r = e.handle(
        &from("OPTIONS", "/api/records", "198.51.100.9"),
        &FakeClock::at(NOW),
    );
    if r.status == 501 {
        panic!("{NOT_IMPLEMENTED}");
    }
    assert_eq!(r.status, 204);
    assert_eq!(h(&r, "access-control-allow-methods"), Some("GET, OPTIONS"));
    assert_eq!(h(&r, "access-control-max-age"), Some("86400"));
    assert_eq!(h(&r, "access-control-allow-origin"), Some("*"));
    assert!(h(&r, "access-control-allow-credentials").is_none());
}

#[test]
fn h5_request_headers_never_change_the_response_or_appear_in_it() {
    let e = explorer();
    let clock = FakeClock::at(NOW);
    let plain = e.handle(&get("/api/head"), &clock);
    if plain.status == 501 {
        panic!("{NOT_IMPLEMENTED}");
    }
    let mut r = get("/api/head");
    r.headers.push((
        "origin".into(),
        "https://evil.example\r\nx-injected: 1".into(),
    ));
    r.headers.push(("cookie".into(), "session=abc".into()));
    r.headers
        .push(("authorization".into(), "Bearer abc".into()));
    r.headers
        .push(("accept-language".into(), "xx\r\nset-cookie: a=b".into()));
    let out = e.handle(&r, &FakeClock::at(NOW + 5000));
    assert_eq!(out.body, plain.body);
    assert_eq!(out.headers, plain.headers);
    for (k, v) in &out.headers {
        assert!(!k.contains('\r') && !k.contains('\n') && !v.contains('\r') && !v.contains('\n'));
    }
}
