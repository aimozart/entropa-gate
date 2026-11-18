//! P0: unique canary tokens in mock records, and the scanner that proves none ever leaks outside the gate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_synthetic::*;
use std::collections::HashSet;

#[test]
fn c1_a_canary_is_prefix_plus_sixteen_lowercase_hex_digits_unique_per_seed() {
    let c = canary(0);
    assert!(
        c.starts_with(CANARY_PREFIX) && c.len() == CANARY_PREFIX.len() + 16,
        "{c}"
    );
    assert!(
        c[CANARY_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{c}"
    );
    assert_eq!(canary(7), canary(7), "deterministic");
    let all: HashSet<String> = (0..10_000u64).map(canary).collect();
    assert_eq!(all.len(), 10_000, "no two seeds share a canary");
    assert_ne!(canary(1), canary(2));
}

#[test]
fn c2_the_scanner_finds_every_canary_in_order_and_nothing_else() {
    let (a, b) = (canary(1), canary(2));
    let text = format!("prefix {a} middle {b}, again {a}.");
    assert_eq!(scan(&text), vec![a.clone(), b.clone(), a.clone()]);
    assert_eq!(
        scan(&format!("{{\"model_id\":\"{a}\"}}")),
        vec![a.clone()],
        "inside JSON"
    );
    assert_eq!(
        scan(&format!("x{a}y")),
        vec![a.clone()],
        "inside a longer word"
    );
    assert!(scan("").is_empty() && scan("nothing here").is_empty());
}

#[test]
fn c3_near_misses_are_not_canaries_but_the_prefix_alone_is_never_ignored_silently() {
    for not in [
        "ENTROPA-CANARY-0123456789abcde",  // 15 digits
        "ENTROPA-CANARY-0123456789ABCDEF", // upper case
        "ENTROPA-CANARY-0123456789abcdeg", // not hex
        "entropa-canary-0123456789abcdef", // lower-case prefix
        "ENTROPA_CANARY_0123456789abcdef",
    ] {
        assert!(scan(not).is_empty(), "{not}");
    }
    // seventeen digits: the first sixteen form a canary (a longer token must not hide one)
    assert_eq!(
        scan("ENTROPA-CANARY-0123456789abcdef0"),
        vec!["ENTROPA-CANARY-0123456789abcdef".to_string()]
    );
}

#[test]
fn c4_every_patient_record_carries_its_canary() {
    for seed in 0..50u64 {
        let p = patient(seed).unwrap();
        assert_eq!(p.canary, canary(seed));
        assert_eq!(
            scan(&format!("{p:?}")),
            vec![canary(seed)],
            "the record exposes exactly its own canary when printed"
        );
    }
}
