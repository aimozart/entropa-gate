//! H1.3 I5a: a tampered or truncated ledger bundle is never reported as verified OK. A mutated bundle that verifies must decode to a JSON value
//! EQUAL to the original (a whitespace-only change is not a tamper); any other OK is an accepted forgery. Generated copies only (throwaway keys
//! of the synthetic generator); no production ledger is read. Fixed seeds, 100,000 cases per property (H13_CASES overrides for a smoke run).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_ledger::verify_bundle;
use proptest::prelude::*;
use proptest::test_runner::{Config as PConfig, RngSeed};
use serde_json::Value;
use std::sync::OnceLock;

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
/// Compare modulo the case of hex strings: the verifier decodes hex, so `3A` and `3a` are the same bytes (a documented limit: the text of a
/// verified bundle is malleable in hex case; the content is not).
fn norm(v: &Value) -> Value {
    match v {
        Value::String(s)
            if s.len() >= 2 && s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit()) =>
        {
            Value::String(s.to_lowercase())
        }
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, c)| (k.clone(), norm(c))).collect()),
        _ => v.clone(),
    }
}
fn bundle() -> &'static String {
    static B: OnceLock<String> = OnceLock::new();
    B.get_or_init(|| run_mem(7, 3).3)
}
fn original() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| serde_json::from_str(bundle()).unwrap())
}

#[derive(Debug, Clone)]
enum Op {
    Flip(usize, u8),
    Delete(usize),
    Insert(usize, u8),
    Truncate(usize),
    DupRange(usize, usize),
    SwapRanges(usize, usize),
    Swap(usize, usize),
}
fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (any::<usize>(), 1u8..=255).prop_map(|(p, x)| Op::Flip(p, x)),
        2 => any::<usize>().prop_map(Op::Delete),
        2 => (any::<usize>(), any::<u8>()).prop_map(|(p, b)| Op::Insert(p, b)),
        1 => any::<usize>().prop_map(Op::Truncate),
        1 => (any::<usize>(), 1usize..400).prop_map(|(p, n)| Op::DupRange(p, n)),
        1 => (any::<usize>(), 1usize..400).prop_map(|(p, n)| Op::SwapRanges(p, n)),
        1 => (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Op::Swap(a, b)),
    ]
}
fn apply(mut b: Vec<u8>, op: &Op) -> Vec<u8> {
    let n = b.len();
    if n == 0 {
        return b;
    }
    match op {
        Op::Flip(p, x) => b[p % n] ^= x,
        Op::Delete(p) => {
            b.remove(p % n);
        }
        Op::Insert(p, x) => b.insert(p % (n + 1), *x),
        Op::Truncate(p) => b.truncate(p % n),
        Op::DupRange(p, len) => {
            let s = p % n;
            let e = (s + len).min(n);
            let chunk = b[s..e].to_vec();
            for (i, x) in chunk.into_iter().enumerate() {
                b.insert(e + i, x);
            }
        }
        Op::SwapRanges(p, len) => {
            let s = p % n;
            let e = (s + len).min(n);
            let t = (s + len + len).min(n);
            if e < t {
                let a = b[s..e].to_vec();
                let c = b[e..t].to_vec();
                b.splice(s..t, c.into_iter().chain(a));
            }
        }
        Op::Swap(a, c) => b.swap(a % n, c % n),
    }
    b
}

proptest! {
    #![proptest_config(cfg(20261112))]
    /// A bundle with one or two byte-level mutations either fails to verify or decodes to the same JSON as the original.
    #[test]
    fn i5a_a_tampered_bundle_never_verifies_unless_it_is_the_same_document(o in op(), o2 in prop::option::of(op())) {
        let mut b = apply(bundle().as_bytes().to_vec(), &o);
        if let Some(o2) = &o2 { b = apply(b, o2); }
        if let Ok(text) = String::from_utf8(b) {
            if verify_bundle(&text).is_ok() {
                let v: Value = serde_json::from_str(&text).expect("a verified bundle is JSON");
                prop_assert!(norm(&v) == norm(original()), "a changed bundle verified OK");
            }
        }
    }
}

proptest! {
    #![proptest_config(cfg(20261113))]
    /// Field-level tampering: change one leaf value of the parsed bundle (string, number, bool), drop a key, or add a key, and re-serialise.
    #[test]
    fn i5a2_a_changed_leaf_or_key_never_verifies(path_pick in any::<usize>(), how in 0u8..5, pos in any::<usize>(), x in any::<u64>()) {
        let mut v = original().clone();
        let mut leaves: Vec<Vec<String>> = Vec::new();
        fn walk(v: &Value, p: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
            match v {
                Value::Object(m) => for (k, c) in m { p.push(k.clone()); walk(c, p, out); p.pop(); },
                Value::Array(a) => for (i, c) in a.iter().enumerate() { p.push(i.to_string()); walk(c, p, out); p.pop(); },
                _ => out.push(p.clone()),
            }
        }
        walk(&v, &mut Vec::new(), &mut leaves);
        let path = &leaves[path_pick % leaves.len()];
        let mut cur = &mut v;
        for (i, k) in path.iter().enumerate() {
            let last = i + 1 == path.len();
            let next = match cur { Value::Object(m) => m.get_mut(k), Value::Array(a) => a.get_mut(k.parse::<usize>().unwrap()), _ => None };
            let Some(next) = next else { return Ok(()); };
            if last {
                match how {
                    0 => match next {
                        Value::String(s) if !s.is_empty() => {
                            let mut cs: Vec<char> = s.chars().collect();
                            let i = pos % cs.len();
                            cs[i] = if cs[i] == 'a' { 'b' } else { 'a' };
                            *s = cs.into_iter().collect();
                        }
                        Value::Number(n) => *next = serde_json::json!(n.as_u64().unwrap_or(0).wrapping_add(1 + x % 5)),
                        Value::Bool(b) => *next = Value::Bool(!*b),
                        _ => *next = Value::String("x".into()),
                    },
                    1 => *next = Value::Null,
                    2 => *next = serde_json::json!(x),
                    3 => *next = Value::String(String::new()),
                    _ => *next = Value::Array(vec![]),
                }
                break;
            }
            cur = next;
        }
        // null is a valid attester: a valid-looking swap, the documented limit (h13_regress.rs w3)
        if how == 1 && path.last().map(String::as_str) == Some("attested_by") { return Ok(()); }
        let text = serde_json::to_string(&v).unwrap();
        if verify_bundle(&text).is_ok() {
            prop_assert!(norm(&v) == norm(original()), "a changed leaf verified OK: {path:?}");
        }
    }
}

/// Exhaustive companion of i5a2: every leaf of a generated bundle, five kinds of change each. Prints (and returns) the leaf paths whose change
/// still verified, with array indices replaced by `*`.
fn unauthenticated_leaves() -> std::collections::BTreeSet<String> {
    fn walk(v: &Value, p: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        match v {
            Value::Object(m) => {
                for (k, c) in m {
                    p.push(k.clone());
                    walk(c, p, out);
                    p.pop();
                }
            }
            Value::Array(a) => {
                for (i, c) in a.iter().enumerate() {
                    p.push(i.to_string());
                    walk(c, p, out);
                    p.pop();
                }
            }
            _ => out.push(p.clone()),
        }
    }
    let mut ls = Vec::new();
    walk(original(), &mut Vec::new(), &mut ls);
    let mut accepted = std::collections::BTreeSet::new();
    for path in &ls {
        for how in 0..5u8 {
            // null is a valid attester: a valid-looking swap, the documented limit (h13_regress.rs w3)
            if how == 1 && path.last().map(String::as_str) == Some("attested_by") {
                continue;
            }
            let mut v = original().clone();
            let mut cur = &mut v;
            for (i, k) in path.iter().enumerate() {
                let next = match cur {
                    Value::Object(m) => m.get_mut(k),
                    Value::Array(a) => a.get_mut(k.parse::<usize>().unwrap()),
                    _ => None,
                };
                let next = next.unwrap();
                if i + 1 == path.len() {
                    match how {
                        0 => match next {
                            Value::String(s) if !s.is_empty() => {
                                let c = if s.starts_with('a') { 'b' } else { 'a' };
                                s.replace_range(0..1, &c.to_string());
                            }
                            Value::Number(n) => {
                                *next = serde_json::json!(n.as_u64().unwrap_or(0) + 1)
                            }
                            Value::Bool(b) => *next = Value::Bool(!*b),
                            _ => *next = Value::String("x".into()),
                        },
                        1 => *next = Value::Null,
                        2 => *next = serde_json::json!(424242u64),
                        3 => *next = Value::String(String::new()),
                        _ => *next = Value::Array(vec![]),
                    }
                    break;
                }
                cur = next;
            }
            if verify_bundle(&serde_json::to_string(&v).unwrap()).is_ok()
                && norm(&v) != norm(original())
            {
                let generic: Vec<String> = path
                    .iter()
                    .map(|k| {
                        if k.chars().all(|c| c.is_ascii_digit()) {
                            "*".to_string()
                        } else {
                            k.clone()
                        }
                    })
                    .collect();
                if std::env::var("H13_VERBOSE").is_ok() {
                    eprintln!(
                        "ACCEPTED {} how={how} was={:?}",
                        path.join("."),
                        original().pointer(&format!("/{}", path.join("/")))
                    );
                }
                accepted.insert(generic.join("."));
            }
        }
    }
    accepted
}

#[test]
fn i5a3_every_leaf_of_the_bundle_is_covered_by_the_verifier() {
    let acc = unauthenticated_leaves();
    assert!(
        acc.is_empty(),
        "leaves whose change still verified: {acc:?}"
    );
}

#[test]
#[ignore = "diagnostic: shows what the shrunk i5a failure changed"]
fn diag_shrunk_flip() {
    let b = bundle().as_bytes().to_vec();
    let p = 11370251119099312408usize % b.len();
    let mut m = b.clone();
    m[p] ^= 32;
    let lo = p.saturating_sub(30);
    eprintln!(
        "ORIG ...{}...",
        String::from_utf8_lossy(&b[lo..(p + 30).min(b.len())])
    );
    eprintln!(
        "MUT  ...{}...",
        String::from_utf8_lossy(&m[lo..(p + 30).min(m.len())])
    );
    eprintln!(
        "verifies: {}",
        verify_bundle(&String::from_utf8(m).unwrap()).is_ok()
    );
}

#[test]
#[ignore = "diagnostic: shows what the shrunk i5a DupRange failure changed"]
fn diag_shrunk_dup() {
    let b = bundle().as_bytes().to_vec();
    let m = apply(b.clone(), &Op::DupRange(8139199203179391589, 116));
    let mt = String::from_utf8(m).unwrap();
    let v: Value = serde_json::from_str(&mt).unwrap();
    fn diff(a: &Value, b: &Value, p: &str, out: &mut Vec<String>) {
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                for (k, c) in x {
                    match y.get(k) {
                        Some(d) => diff(c, d, &format!("{p}.{k}"), out),
                        None => out.push(format!("{p}.{k} removed")),
                    }
                }
                for k in y.keys() {
                    if !x.contains_key(k) {
                        out.push(format!("{p}.{k} added"))
                    }
                }
            }
            (Value::Array(x), Value::Array(y)) => {
                if x.len() != y.len() {
                    out.push(format!("{p} len {} -> {}", x.len(), y.len()))
                }
                for (i, (c, d)) in x.iter().zip(y).enumerate() {
                    diff(c, d, &format!("{p}[{i}]"), out)
                }
            }
            _ => {
                if a != b {
                    out.push(format!("{p}: {:?} -> {:?}", a, b))
                }
            }
        }
    }
    let mut out = Vec::new();
    diff(original(), &v, "", &mut out);
    for o in out.iter().take(6) {
        eprintln!("DIFF {}", &o[..o.len().min(1500)]);
    }
    eprintln!("verifies: {}", verify_bundle(&mt).is_ok());
}

#[test]
#[ignore = "diagnostic: where the witness statement changed"]
fn diag_witness_dup() {
    let b = bundle().as_bytes().to_vec();
    let mt = String::from_utf8(apply(b, &Op::DupRange(8139199203179391589, 116))).unwrap();
    let v: Value = serde_json::from_str(&mt).unwrap();
    let (a, c) = (
        original()["witnesses"][1].as_str().unwrap(),
        v["witnesses"][1].as_str().unwrap(),
    );
    let i = a.chars().zip(c.chars()).take_while(|(x, y)| x == y).count();
    eprintln!("LEN {} -> {}; first difference at {}", a.len(), c.len(), i);
    eprintln!(
        "ORIG ...{}...",
        &a[i.saturating_sub(20)..(i + 60).min(a.len())]
    );
    eprintln!(
        "NEW  ...{}...",
        &c[i.saturating_sub(20)..(i + 60).min(c.len())]
    );
    eprintln!("tail ORIG {}", &a[a.len().saturating_sub(40)..]);
    eprintln!("tail NEW  {}", &c[c.len().saturating_sub(40)..]);
}
