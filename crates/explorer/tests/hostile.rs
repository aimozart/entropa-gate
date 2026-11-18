//! Hostile inputs never panic, always answer valid JSON, and never echo what they sent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use proptest::prelude::*;

#[test]
fn x1_known_attacks_get_fixed_answers_without_an_echo() {
    let e = explorer();
    let marker = "zzmarkerzz";
    let attacks = [
        format!("/api/../{marker}"),
        format!("/api/records/{marker}"),
        format!("/api/actors/{marker}"),
        format!("/api/records?limit={marker}"),
        format!("/api/records?{marker}=1"),
        format!("/api/records?tenant={marker}"),
        format!("/{marker}"),
        format!("/api/records/%00{marker}"),
        format!("/api/records/\u{202e}{marker}"),
        format!("/api/records?limit=1\r\nx-injected: {marker}"),
        format!("/api/{}", "../".repeat(200)),
        format!("/api/actors/{}{marker}", "\u{1F600}".repeat(100)),
    ];
    for a in attacks {
        let r = ask(&e, &a);
        assert!(matches!(r.status, 400 | 404 | 414), "{a:?} -> {}", r.status);
        assert!(!r.body.contains(marker), "{a:?} was echoed");
        assert!(json(&r)["error"].is_string());
        assert!(!r.headers.values().any(|v| v.contains(marker)));
    }
}

#[test]
fn x2_a_huge_limit_cannot_widen_the_page() {
    let e = explorer();
    for l in ["1000", "100000000", "18446744073709551616"] {
        assert_eq!(ask(&e, &format!("/api/records?limit={l}")).status, 400);
    }
}

/// One explorer for all cases (verifying the bundle is the slow part); every case uses a fresh client so the
/// limiter never interferes.
fn shared() -> &'static Explorer {
    static E: std::sync::OnceLock<Explorer> = std::sync::OnceLock::new();
    E.get_or_init(explorer)
}

/// Every fixed error text the API can answer with; a needle may only appear in a body if it is part of this.
const FIXED: &str =
    "bad_request not_found method_not_allowed rate_limited uri_too_long response_too_large";

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn x3_any_path_and_query_gives_valid_json_and_no_echo(path in "\\PC{6,80}", query in "\\PC{6,80}") {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let client = format!("client-{}", N.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        let mut req = from("GET", "/", &client);
        req.path = format!("/api/{path}");
        req.query = query.clone();
        let r = shared().handle(&req, &FakeClock::at(NOW));
        if r.status == 501 { panic!("{NOT_IMPLEMENTED}"); }
        prop_assert!(serde_json::from_str::<serde_json::Value>(&r.body).is_ok() || r.body.is_empty());
        // No response, of any status, echoes what the client sent (path or query, 6+ characters).
        for needle in [&path, &query] {
            prop_assert!(!r.body.contains(needle.as_str()) || FIXED.contains(needle.as_str()), "echoed {needle:?}");
            for v in r.headers.values() {
                prop_assert!(!v.contains(needle.as_str()), "header echoed {needle:?}");
            }
        }
    }
}
