//! Exact boundaries of the caps, the paging and the limiter, pinned after mutation testing (S7e).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[test]
fn z1_a_path_of_exactly_the_cap_is_served_and_one_more_byte_is_not() {
    let e = explorer();
    let at_cap = format!("/api/actors/{}", "a".repeat(256 - "/api/actors/".len()));
    assert_eq!(at_cap.len(), 256);
    assert_eq!(
        ask(&e, &at_cap).status,
        404,
        "256 bytes is allowed (then simply not found)"
    );
    assert_eq!(ask(&e, &format!("{at_cap}a")).status, 414);
}

#[test]
fn z2_a_query_of_exactly_the_cap_is_parsed_and_one_more_byte_is_not() {
    let e = explorer();
    let at_cap = format!("/api/records?tenant={}", "a".repeat(512 - "tenant=".len()));
    assert_eq!(at_cap.split_once('?').unwrap().1.len(), 512);
    assert_eq!(
        ask(&e, &at_cap).status,
        400,
        "512 bytes is parsed (and refused as an unknown tenant)"
    );
    assert_eq!(ask(&e, &format!("{at_cap}a")).status, 414);
}

#[test]
fn z3_a_body_of_exactly_the_response_cap_is_served_and_one_byte_less_is_not() {
    let body = ask(&explorer(), "/api/healthz").body;
    assert_eq!(body, r#"{"status":"ok"}"#);
    let fits = Limits {
        max_response_bytes: body.len(),
        ..Limits::default()
    };
    assert_eq!(ask(&explorer_with(fits), "/api/healthz").status, 200);
    let short = Limits {
        max_response_bytes: body.len() - 1,
        ..Limits::default()
    };
    assert_eq!(ask(&explorer_with(short), "/api/healthz").status, 500);
}

#[test]
fn z4_the_next_cursor_appears_only_when_older_items_remain() {
    let e = explorer();
    let total = fixture()["records"].as_array().unwrap().len();
    let all = json(&ask(&e, &format!("/api/records?limit={total}")));
    assert_eq!(all["items"].as_array().unwrap().len(), total);
    assert!(
        all["next_cursor"].is_null(),
        "exactly the remaining count: nothing older"
    );
    let one_short = json(&ask(&e, &format!("/api/records?limit={}", total - 1)));
    assert_eq!(
        one_short["next_cursor"], 1,
        "the lowest index returned, one item remains"
    );
    let cps = json(&ask(&e, "/api/checkpoints?limit=2"));
    assert!(cps["next_cursor"].is_null());
    assert_eq!(json(&ask(&e, "/api/checkpoints?limit=1"))["next_cursor"], 1);
}

#[test]
fn z5_tracked_clients_counts_the_distinct_clients_served() {
    let e = explorer();
    let c = FakeClock::at(NOW);
    for client in [
        "198.51.100.1",
        "198.51.100.2",
        "198.51.100.1",
        "198.51.100.3",
    ] {
        assert_eq!(
            e.handle(&from("GET", "/api/healthz", client), &c).status,
            200
        );
    }
    assert_eq!(e.tracked_clients(), 3);
}

#[test]
fn z6_retry_after_counts_the_missing_part_of_a_token() {
    // 30 per minute = half a token per second: an empty bucket waits 2 s, one that has half a token waits 1 s.
    let e = explorer_with(Limits {
        rate_per_minute: 30,
        ..Limits::default()
    });
    let c = FakeClock::at(NOW);
    let hit = || e.handle(&from("GET", "/api/healthz", CLIENT), &c);
    for _ in 0..20 {
        assert_eq!(hit().status, 200);
    }
    let r = hit();
    assert_eq!(
        (r.status, r.headers.get("retry-after").map(String::as_str)),
        (429, Some("2"))
    );
    c.advance(1);
    let r = hit();
    assert_eq!(
        (r.status, r.headers.get("retry-after").map(String::as_str)),
        (429, Some("1"))
    );
    c.advance(1);
    assert_eq!(hit().status, 200);
}
