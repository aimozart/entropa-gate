//! Rate limit: 60/min per client, burst 20, refill 1/s, injected clock, bounded memory.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

fn hit(e: &Explorer, c: &FakeClock, client: &str) -> Response {
    let r = e.handle(&from("GET", "/api/healthz", client), c);
    if r.status == 501 {
        panic!("{NOT_IMPLEMENTED}");
    }
    r
}

#[test]
fn l1_the_twenty_first_request_in_the_same_second_is_limited() {
    let e = explorer();
    let c = FakeClock::at(NOW);
    for i in 0..20 {
        assert_eq!(hit(&e, &c, CLIENT).status, 200, "request {i}");
    }
    let r = hit(&e, &c, CLIENT);
    assert_eq!(r.status, 429);
    assert_eq!(r.headers.get("retry-after").map(String::as_str), Some("1"));
    assert_eq!(json(&r)["error"], "rate_limited");
    assert_eq!(
        r.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
}

#[test]
fn l2_tokens_refill_one_per_second_up_to_the_burst() {
    let e = explorer();
    let c = FakeClock::at(NOW);
    for _ in 0..20 {
        hit(&e, &c, CLIENT);
    }
    assert_eq!(hit(&e, &c, CLIENT).status, 429);
    c.advance(1);
    assert_eq!(hit(&e, &c, CLIENT).status, 200);
    assert_eq!(hit(&e, &c, CLIENT).status, 429);
    c.advance(3600);
    for i in 0..20 {
        assert_eq!(
            hit(&e, &c, CLIENT).status,
            200,
            "after a long pause, request {i}"
        );
    }
    assert_eq!(
        hit(&e, &c, CLIENT).status,
        429,
        "the bucket never exceeds 20"
    );
}

#[test]
fn l3_sixty_requests_in_a_minute_is_the_ceiling() {
    let e = explorer();
    let c = FakeClock::at(NOW);
    let mut ok = 0;
    for _ in 0..120 {
        if hit(&e, &c, CLIENT).status == 200 {
            ok += 1;
        }
        c.advance(1);
        if (c.0.get() - NOW).is_multiple_of(2) {
            hit(&e, &c, CLIENT);
        }
    }
    // 20 burst + 1 per second over 120 s, never more than 60 a minute once the burst is spent.
    assert!(ok <= 20 + 120, "{ok}");
    let c2 = FakeClock::at(NOW);
    let e2 = explorer();
    let mut served = 0;
    for s in 0..60u64 {
        c2.0.set(NOW + s);
        for _ in 0..5 {
            if hit(&e2, &c2, CLIENT).status == 200 {
                served += 1;
            }
        }
    }
    assert!(served <= 80, "a minute of hammering served {served}");
    assert!(served >= 60, "a minute of hammering served {served}");
}

#[test]
fn l4_clients_are_independent_and_forwarded_headers_are_ignored() {
    let e = explorer();
    let c = FakeClock::at(NOW);
    for _ in 0..20 {
        hit(&e, &c, "203.0.113.1");
    }
    assert_eq!(hit(&e, &c, "203.0.113.1").status, 429);
    assert_eq!(hit(&e, &c, "203.0.113.2").status, 200);
    let mut spoof = from("GET", "/api/healthz", "203.0.113.1");
    spoof
        .headers
        .push(("x-forwarded-for".into(), "198.51.100.77".into()));
    spoof
        .headers
        .push(("x-real-ip".into(), "198.51.100.78".into()));
    assert_eq!(
        e.handle(&spoof, &c).status,
        429,
        "a spoofed header must not buy a fresh bucket"
    );
}

#[test]
fn l5_the_tracked_client_table_is_bounded() {
    let limits = Limits {
        max_tracked_clients: 50,
        ..Limits::default()
    };
    let e = explorer_with(limits);
    let c = FakeClock::at(NOW);
    for i in 0..500 {
        assert_eq!(
            hit(&e, &c, &format!("10.0.{}.{}", i / 250, i % 250)).status,
            200
        );
    }
    assert!(e.tracked_clients() <= 50, "{}", e.tracked_clients());
}

#[test]
fn l6_a_clock_that_goes_backwards_never_panics_or_mints_tokens() {
    let e = explorer();
    let c = FakeClock::at(NOW);
    for _ in 0..20 {
        hit(&e, &c, CLIENT);
    }
    c.0.set(NOW - 1000);
    assert_eq!(hit(&e, &c, CLIENT).status, 429);
}

#[test]
fn l7_limited_responses_still_carry_the_security_and_cors_headers() {
    let e = explorer();
    let c = FakeClock::at(NOW);
    for _ in 0..20 {
        hit(&e, &c, CLIENT);
    }
    let r = hit(&e, &c, CLIENT);
    assert_eq!(r.status, 429);
    assert_eq!(
        r.headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("*")
    );
    assert_eq!(
        r.headers.get("x-content-type-options").map(String::as_str),
        Some("nosniff")
    );
}
