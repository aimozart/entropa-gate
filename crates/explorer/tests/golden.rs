//! Golden responses produced by the independent generator docs/evidence/s7d-gen-golden.py.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::Value;

const GOLDEN: &str = include_str!("golden/responses.json");

#[test]
fn g1_every_golden_target_answers_byte_for_byte() {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    let map = golden.as_object().unwrap();
    assert!(map.len() >= 30, "{} golden responses", map.len());
    // Each target gets its own explorer so the limiter never interferes.
    for (target, body) in map {
        let r = ask(&explorer(), target);
        assert_eq!(r.status, 200, "{target}");
        assert_eq!(r.body, body.as_str().unwrap(), "{target}");
    }
}

#[test]
fn g2_bodies_are_canonical_compact_json() {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    for target in golden.as_object().unwrap().keys().take(12) {
        let r = ask(&explorer(), target);
        assert_eq!(r.body, canonical(&json(&r)), "{target}");
    }
}
