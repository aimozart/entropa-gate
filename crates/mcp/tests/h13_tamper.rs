//! H1.3 I5b: a tampered receipt or checkpoint is never reported valid by the MCP verify tools. A mutated receipt that is reported valid must
//! decode to a receipt EQUAL to the original (hex upper or lower case is the same bytes). Generated logs with throwaway keys only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::transparency_log::{Checkpoint, Receipt};
use proptest::prelude::*;
use proptest::test_runner::{Config as PConfig, RngSeed};
use serde_json::{json, Value};

fn cases() -> u32 {
    std::env::var("H13_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000)
}
fn cfg(seed: u64) -> PConfig {
    PConfig {
        cases: cases(),
        rng_seed: RngSeed::Fixed(seed),
        max_shrink_iters: 4096,
        ..PConfig::default()
    }
}
fn leaves(v: &Value, p: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match v {
        Value::Object(m) => {
            for (k, c) in m {
                p.push(k.clone());
                leaves(c, p, out);
                p.pop();
            }
        }
        Value::Array(a) => {
            for (i, c) in a.iter().enumerate() {
                p.push(i.to_string());
                leaves(c, p, out);
                p.pop();
            }
        }
        _ => out.push(p.clone()),
    }
}
fn mutate(v: &mut Value, pick: usize, how: u8, pos: usize, x: u64) -> bool {
    let mut ls = Vec::new();
    leaves(v, &mut Vec::new(), &mut ls);
    if ls.is_empty() {
        return false;
    }
    let path = ls[pick % ls.len()].clone();
    let mut cur = v;
    for (i, k) in path.iter().enumerate() {
        let next = match cur {
            Value::Object(m) => m.get_mut(k),
            Value::Array(a) => a.get_mut(k.parse::<usize>().unwrap()),
            _ => None,
        };
        let Some(next) = next else { return false };
        if i + 1 == path.len() {
            match (how, &mut *next) {
                (0, Value::String(s)) if !s.is_empty() => {
                    let mut cs: Vec<char> = s.chars().collect();
                    let j = pos % cs.len();
                    cs[j] = match cs[j] {
                        '0' => '1',
                        'a' => 'b',
                        _ => '0',
                    };
                    *s = cs.into_iter().collect();
                }
                (0, Value::Number(n)) => {
                    *next = json!(n.as_u64().unwrap_or(0).wrapping_add(1 + x % 7))
                }
                (1, _) => *next = Value::Null,
                (2, _) => *next = json!(x),
                (3, _) => *next = Value::String(String::new()),
                (4, Value::String(s)) => {
                    s.truncate(s.len() / 2);
                }
                (5, Value::String(s)) => {
                    *s = s.to_uppercase();
                }
                _ => *next = json!(x % 3),
            }
            return true;
        }
        cur = next;
    }
    false
}

proptest! {
    #![proptest_config(cfg(20261114))]
    /// verify_receipt: one mutation of any field of a good receipt is never "valid" unless it decodes to the same receipt.
    #[test]
    fn i5b_a_tampered_receipt_is_never_valid(n in 1usize..8, idx in any::<usize>(), pick in any::<usize>(), how in 0u8..7, pos in any::<usize>(), x in any::<u64>(), second in any::<bool>()) {
        let w = world(n);
        let r: Receipt = w.receipt(idx % n);
        let base = receipt_json(&r);
        let mut m = base.clone();
        if !mutate(&mut m, pick, how, pos, x) { return Ok(()); }
        if second { let _ = mutate(&mut m, pick.wrapping_mul(31), how, pos.wrapping_add(7), x ^ 0x55); }
        let mut s = w.server_no_source();
        let out = s.call_at("verify_receipt", &json!({"receipt": m.clone()}), T0);
        if !out.is_error && out.body["valid"] == json!(true) {
            let same = serde_json::from_value::<Receipt>(m.clone()).ok().map(|r2| r2 == r).unwrap_or(false);
            prop_assert!(same, "a changed receipt was valid: {m}");
        }
    }
}

proptest! {
    #![proptest_config(cfg(20261115))]
    /// verify_checkpoint: a mutated checkpoint is never "signature_valid" and "signer_trusted" unless it decodes to the same checkpoint.
    #[test]
    fn i5b2_a_tampered_checkpoint_is_never_trusted(n in 1usize..8, pick in any::<usize>(), how in 0u8..7, pos in any::<usize>(), x in any::<u64>()) {
        let w = world(n);
        let base = cp_json(&w.head);
        let mut m = base.clone();
        if !mutate(&mut m, pick, how, pos, x) { return Ok(()); }
        let mut s = w.server_no_source();
        let out = s.call_at("verify_checkpoint", &json!({"checkpoint": m.clone()}), T0);
        if !out.is_error && out.body["signature_valid"] == json!(true) && out.body["signer_trusted"] == json!(true) {
            let same = serde_json::from_value::<Checkpoint>(m.clone()).ok().map(|c| c == w.head).unwrap_or(false);
            prop_assert!(same, "a changed checkpoint was trusted: {m}");
        }
    }
}
