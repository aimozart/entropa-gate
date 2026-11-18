//! EG1b: an access-key id is a 4-letter prefix plus 16 upper-case alphanumerics (EG0 section 4, D1). The engine used the base32 alphabet
//! [A-Z2-7] and allowed any key whose tail held 0, 1, 8 or 9 (found by the sealed run of 2026-11-14). Synthetic ids only; the expected values are
//! written by hand here, not produced by the code under test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action};
use entropa_egress::policy::Tier;

fn act(body: &str) -> Action {
    decide(&text_req(body), &policy(), Tier::T1, &conv(), &Mem::new()).action()
}

#[test]
fn a1_keys_with_digits_outside_base32_are_blocked() {
    for k in [
        "AKIAQWERTY0189ABCDEF",
        "AKIA1234567890ABCDEF",
        "ASIA0000000000000000",
        "AKIAZZZZZZZZZZZZZZ89",
    ] {
        assert_eq!(act(&format!("key {k} end")), Action::Block, "{k}");
    }
}

#[test]
fn a2_the_base32_example_key_is_still_blocked() {
    assert_eq!(act("key AKIAIOSFODNN7EXAMPLE end"), Action::Block);
}

#[test]
fn a3_near_misses_are_still_allowed() {
    // 15 characters after the prefix, a separator inside the tail (not a chunked token), and a prefix that is not a provider prefix. A key
    // glued inside a longer word stays blocked on purpose (the stripped view is unbounded, as for the base32 form before this change).
    for t in [
        "key AKIAQWERTY0189ABCDE end",
        "key AKIA QWERTY0189 ABCDEF end",
        "key BKIAQWERTY0189ABCDEF end",
    ] {
        assert_eq!(act(t), Action::Allow, "{t}");
    }
}
