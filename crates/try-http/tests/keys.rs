//! LS3b red tests, part 1: the client key behind a proxy and the global caps (a stage record (not published), LS3b.md sections 2 and 4). Pure functions, no sockets. Expected values are written by hand from the rule.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_try_http::{client_key, Caps};
use std::net::IpAddr;

fn peer() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

#[test]
fn k1_the_entry_counted_from_the_right_is_the_key_and_forged_left_entries_are_ignored() {
    assert_eq!(client_key(Some("9.9.9.9"), 1, peer()), "9.9.9.9");
    assert_eq!(
        client_key(Some("1.1.1.1, 2.2.2.2, 9.9.9.9"), 1, peer()),
        "9.9.9.9"
    );
    assert_eq!(
        client_key(Some("1.1.1.1, 2.2.2.2, 9.9.9.9"), 2, peer()),
        "2.2.2.2"
    );
    assert_eq!(
        client_key(Some("1.1.1.1,2.2.2.2,9.9.9.9"), 3, peer()),
        "1.1.1.1"
    );
    // the forged left entries differ, the real one does not: the same key
    assert_eq!(
        client_key(Some("6.6.6.6, 9.9.9.9"), 1, peer()),
        client_key(Some("7.7.7.7, 8.8.8.8, 9.9.9.9"), 1, peer())
    );
    // spaces and tabs around entries are ignored
    assert_eq!(
        client_key(Some("  1.1.1.1 ,\t9.9.9.9  "), 1, peer()),
        "9.9.9.9"
    );
}

#[test]
fn k2_a_short_header_a_missing_header_or_a_non_ip_entry_uses_the_peer() {
    assert_eq!(client_key(None, 1, peer()), "127.0.0.1");
    assert_eq!(client_key(Some(""), 1, peer()), "127.0.0.1");
    assert_eq!(
        client_key(Some("9.9.9.9"), 2, peer()),
        "127.0.0.1",
        "fewer entries than hops"
    );
    assert_eq!(
        client_key(Some("1.1.1.1, not-an-ip"), 1, peer()),
        "127.0.0.1"
    );
    assert_eq!(
        client_key(Some("1.1.1.1:8080"), 1, peer()),
        "127.0.0.1",
        "a port is not a plain address"
    );
    assert_eq!(
        client_key(Some("[2001:db8::1]"), 1, peer()),
        "127.0.0.1",
        "brackets are not a plain address"
    );
    assert_eq!(
        client_key(Some("fe80::1%eth0"), 1, peer()),
        "127.0.0.1",
        "a zone is not a plain address"
    );
    assert_eq!(
        client_key(Some("1.1.1.1,,9.9.9.9"), 2, peer()),
        "127.0.0.1",
        "an empty entry is not an address"
    );
}

#[test]
fn k3_zero_hops_ignores_the_header_entirely() {
    assert_eq!(client_key(Some("9.9.9.9"), 0, peer()), "127.0.0.1");
    assert_eq!(
        client_key(Some("1.1.1.1, 9.9.9.9"), 0, "203.0.113.5".parse().unwrap()),
        "203.0.113.5"
    );
}

#[test]
fn k4_ipv6_is_reduced_to_its_64_and_ipv4_mapped_is_ipv4() {
    assert_eq!(
        client_key(Some("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), 1, peer()),
        "2001:db8:1:2::/64"
    );
    assert_eq!(
        client_key(Some("2001:db8:1:2::1"), 1, peer()),
        client_key(Some("2001:db8:1:2:ffff:ffff:ffff:ffff"), 1, peer())
    );
    assert_ne!(
        client_key(Some("2001:db8:1:2::1"), 1, peer()),
        client_key(Some("2001:db8:1:3::1"), 1, peer())
    );
    assert_eq!(client_key(Some("::ffff:1.2.3.4"), 1, peer()), "1.2.3.4");
    assert_eq!(client_key(Some("::1"), 1, peer()), "0:0:0:0::/64");
    // an IPv6 peer is reduced the same way
    assert_eq!(
        client_key(None, 1, "2001:db8:5:6:1:2:3:4".parse().unwrap()),
        "2001:db8:5:6::/64"
    );
}

const T: u64 = 1_800_000_000 - (1_800_000_000 % 86_400) + 1_000; // 1,000 s after a UTC midnight

#[test]
fn k5_the_global_cap_refuses_with_busy_and_a_retry_after_to_the_end_of_the_window() {
    let mut c = Caps::new(5, 1_000);
    for i in 0..5 {
        assert_eq!(c.admit(T + i), Ok(()), "request {i}");
    }
    let r = c.admit(T + 10).unwrap_err();
    assert_eq!(r.code, "busy");
    assert_eq!(
        r.retry_after, 50,
        "the window opened at T, so 60 - 10 seconds remain"
    );
    // refused attempts do not extend the window
    let r = c.admit(T + 30).unwrap_err();
    assert_eq!((r.code, r.retry_after), ("busy", 30));
    // the next window starts at T + 60
    assert_eq!(c.admit(T + 60), Ok(()));
    assert_eq!(c.admit(T + 59 + 60), Ok(()));
}

#[test]
fn k6_the_daily_cap_refuses_with_daily_limit_until_the_next_utc_day() {
    let mut c = Caps::new(1_000_000, 3);
    for i in 0..3 {
        assert_eq!(c.admit(T + i * 100), Ok(()), "request {i}");
    }
    let r = c.admit(T + 400).unwrap_err();
    assert_eq!(r.code, "daily_limit");
    assert_eq!(
        r.retry_after,
        86_400 - 1_400,
        "seconds to the next midnight"
    );
    // still refused later the same day, even in a fresh minute
    assert_eq!(c.admit(T + 5_000).unwrap_err().code, "daily_limit");
    // the next UTC day starts afresh
    assert_eq!(c.admit(T - 1_000 + 86_400), Ok(()));
}

#[test]
fn k7_when_both_caps_apply_the_daily_one_is_reported() {
    let mut c = Caps::new(2, 2);
    assert_eq!(c.admit(T), Ok(()));
    assert_eq!(c.admit(T + 1), Ok(()));
    assert_eq!(c.admit(T + 2).unwrap_err().code, "daily_limit");
}
