//! Strict query parsing: anything not exactly allowed is a 400 with a fixed error code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[test]
fn q1_these_queries_are_all_bad_requests() {
    // One explorer per query: 30 queries from one client would (rightly) hit the 20-request burst.
    let bad = [
        "/api/records?limit=0",
        "/api/records?limit=101",
        "/api/records?limit=-1",
        "/api/records?limit=007",
        "/api/records?limit=1e1",
        "/api/records?limit=99999999999999999999",
        "/api/records?limit=",
        "/api/records?limit=5&limit=6",
        "/api/records?nothing=1",
        "/api/records?cursor=9007199254740992",
        "/api/records?cursor=x",
        "/api/records?tenant=nobody",
        "/api/records?kind=drop.table",
        "/api/records?actor=spock",
        "/api/records?tenant=entropa&tenant=bigironbank",
        "/api/records?limit=5%30",
        "/api/records?limit=5+",
        "/api/records?limit=\u{0661}",
        "/api/records?tenant=entr\u{00f6}pa",
        "/api/records?limit=5&",
        "/api/records?&limit=5",
        "/api/records?limit",
        "/api/records?=5",
        "/api/head?limit=1",
        "/api/healthz?x=1",
        "/api/consistency?old=9",
        "/api/consistency?old=9&new=x",
        "/api/consistency?old=9&new=25&old=9",
        "/api/witnesses?size=-1",
        "/api/receipts/3?size=",
    ];
    for t in bad {
        let r = ask(&explorer(), t);
        assert_eq!(r.status, 400, "{t}");
        assert_eq!(json(&r)["error"], "bad_request", "{t}");
    }
}

#[test]
fn q2_limits_at_the_edge_are_accepted() {
    let e = explorer();
    assert_eq!(
        json(&ask(&e, "/api/records?limit=1"))["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        json(&ask(&e, "/api/records?limit=100"))["items"]
            .as_array()
            .unwrap()
            .len(),
        25
    );
    assert_eq!(ask(&e, "/api/records?cursor=0").status, 200);
    assert_eq!(
        json(&ask(&e, "/api/records?cursor=0"))["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(ask(&e, "/api/records?cursor=9007199254740991").status, 200);
}

#[test]
fn q3_filters_combine_with_and() {
    let e = explorer();
    let v = json(&ask(&e, "/api/records?tenant=entropa&kind=directory.actor"));
    for it in v["items"].as_array().unwrap() {
        assert_eq!(it["tenant"], "entropa");
        assert_eq!(it["kind"], "directory.actor");
    }
    assert!(!v["items"].as_array().unwrap().is_empty());
}

#[test]
fn q4_path_and_query_caps_and_path_shape() {
    let e = explorer();
    let long_path = format!("/api/actors/{}", "a".repeat(300));
    assert_eq!(ask(&e, &long_path).status, 414);
    let long_query = format!("/api/records?tenant={}", "a".repeat(600));
    assert_eq!(ask(&e, &long_query).status, 414);
    for p in [
        "/api/../etc/passwd",
        "/api//head",
        "/api/records/%2e%2e",
        "/api\\head",
        "/api/head\0",
        "/api/records/\u{0661}",
        "/api/ACTORS",
        "/api/actors/Human-Principal",
    ] {
        let s = ask(&e, p).status;
        assert!(s == 400 || s == 404, "{p:?} -> {s}");
    }
}

#[test]
fn q5_a_response_over_the_size_cap_is_refused_not_truncated() {
    let tiny = Limits {
        max_response_bytes: 2_000,
        ..Limits::default()
    };
    let e = explorer_with(tiny);
    let r = ask(&e, "/api/records/0");
    assert_eq!(r.status, 500);
    assert_eq!(json(&r)["error"], "response_too_large");
    assert_eq!(ask(&e, "/api/healthz").status, 200);
}
