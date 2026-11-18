//! AT1 task 2: hostile-input and property tests. 100,000 cases per property, fixed seeds (AT1_CASES overrides for a smoke run).
//! T4: any bytes: no panic, deterministic, closed reason. T1: a mutated valid token never verifies unless it is the same bytes.
//! T2: random narrowing sequences never exceed the root, checked against an independent model. B2: valid tokens verify.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tokens::canon::{parse, write};
use entropa_tokens::testing::append_c_unchecked;
use entropa_tokens::{
    append_c, issue_a, issue_c, verify_a, verify_c, Claims, Deny, Narrowing, Policy, Tier, Trust,
    Wallet,
};
use proptest::prelude::*;
use proptest::test_runner::{Config as PConfig, RngSeed};
use std::sync::OnceLock;

const NOW: u64 = 1_800_000_000;

fn cases() -> u32 {
    std::env::var("AT1_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000)
}
fn cfg(seed: u64) -> PConfig {
    PConfig {
        cases: cases(),
        rng_seed: RngSeed::Fixed(seed),
        max_shrink_iters: 4096,
        max_global_rejects: 1_000_000,
        ..PConfig::default()
    }
}
fn corpus(i: usize) -> String {
    format!("{:02x}", i + 0x10).repeat(32)
}
const ACTIONS: [&str; 6] = [
    "cite_check",
    "list_versions",
    "lookup_clause",
    "read",
    "search",
    "write",
];
fn root_claims() -> Claims {
    Claims {
        token_id: "e".repeat(32),
        subject: "agent-p".into(),
        tier: Tier::T3,
        corpora: (0..6).map(corpus).collect(),
        actions: ACTIONS.iter().map(ToString::to_string).collect(),
        spend_cap: 10_000_000,
        rate_cap: 600,
        not_before: NOW - 100,
        expiry: NOW + 3000,
        audience: "node-1".into(),
        parent: None,
    }
}
fn policy() -> Policy {
    Policy {
        audience: "node-1".into(),
        now: NOW,
        ..Policy::default()
    }
}
struct World {
    issuer: Probe,
    trust: Trust,
    rev: Vec<u8>,
}
fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let issuer = Probe::spawn();
        let mut trust = Trust::default();
        trust.add(&issuer.pubkey_hex());
        let rev = entropa_tokens::empty_revocations(&issuer, NOW);
        World { issuer, trust, rev }
    })
}
fn base_a() -> &'static Vec<u8> {
    static B: OnceLock<Vec<u8>> = OnceLock::new();
    B.get_or_init(|| issue_a(&world().issuer, &root_claims()).unwrap())
}
fn base_c() -> &'static Vec<u8> {
    static B: OnceLock<Vec<u8>> = OnceLock::new();
    B.get_or_init(|| {
        let w = issue_c(&world().issuer, &root_claims()).unwrap();
        let w = append_c(
            &w,
            &Narrowing {
                tier: Some(Tier::T2),
                ..Narrowing::default()
            },
        )
        .unwrap();
        append_c(
            &w,
            &Narrowing {
                spend_cap: Some(500),
                ..Narrowing::default()
            },
        )
        .unwrap()
        .token
    })
}

#[derive(Debug, Clone)]
enum Op {
    Flip(usize, u8),
    Delete(usize),
    Insert(usize, u8),
    Truncate(usize),
    Dup(usize, usize),
    Swap(usize, usize),
    Splice(usize, Vec<u8>),
}
fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (any::<usize>(), 1u8..=255).prop_map(|(p, x)| Op::Flip(p, x)),
        2 => any::<usize>().prop_map(Op::Delete),
        2 => (any::<usize>(), any::<u8>()).prop_map(|(p, b)| Op::Insert(p, b)),
        1 => any::<usize>().prop_map(Op::Truncate),
        1 => (any::<usize>(), 1usize..300).prop_map(|(p, n)| Op::Dup(p, n)),
        1 => (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Op::Swap(a, b)),
        1 => (any::<usize>(), prop::collection::vec(prop::sample::select(b"{}[]\",:0123456789abcdef \\\n".to_vec()), 1..12)).prop_map(|(p, v)| Op::Splice(p, v)),
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
        Op::Dup(p, len) => {
            let s = p % n;
            let e = (s + len).min(n);
            let chunk = b[s..e].to_vec();
            for (i, x) in chunk.into_iter().enumerate() {
                b.insert(e + i, x);
            }
        }
        Op::Swap(a, c) => b.swap(a % n, c % n),
        Op::Splice(p, v) => {
            let s = p % (n + 1);
            for (i, x) in v.iter().enumerate() {
                b.insert(s + i, *x);
            }
        }
    }
    b
}

proptest! {
    #![proptest_config(cfg(20261201))]
    /// T4: arbitrary bytes into both verifiers and the reader: no panic, the same answer twice, a closed reason.
    #[test]
    fn p1_hostile_bytes_never_panic_and_always_give_a_closed_deterministic_answer(b in prop::collection::vec(any::<u8>(), 0..3000), cut in any::<usize>()) {
        let w = world();
        for bytes in [b.clone(), b[..cut % (b.len() + 1)].to_vec()] {
            let r1 = verify_a(&bytes, &w.trust, &policy(), Some(&w.rev), None);
            let r2 = verify_a(&bytes, &w.trust, &policy(), Some(&w.rev), None);
            prop_assert_eq!(&r1, &r2);
            prop_assert!(r1.is_err(), "random bytes verified");
            let c1 = verify_c(&bytes, &w.trust, &policy(), Some(&w.rev));
            prop_assert_eq!(&c1, &verify_c(&bytes, &w.trust, &policy(), Some(&w.rev)));
            prop_assert!(c1.is_err());
            if let Err(d) = r1 { prop_assert!(!d.as_str().is_empty()); }
            let _ = parse(&bytes);
        }
    }
}

proptest! {
    #![proptest_config(cfg(20261202))]
    /// T1 (design A): one or two byte-level mutations of a valid token never verify unless the bytes are unchanged.
    #[test]
    fn p2_a_mutated_design_a_token_never_verifies(o in op(), o2 in prop::option::of(op())) {
        let w = world();
        let mut m = apply(base_a().clone(), &o);
        if let Some(o2) = &o2 { m = apply(m, o2); }
        if verify_a(&m, &w.trust, &policy(), Some(&w.rev), None).is_ok() {
            prop_assert!(&m == base_a(), "a changed token verified");
        }
    }
}

proptest! {
    #![proptest_config(cfg(20261203))]
    /// T1 (design C): the same for a root plus two blocks.
    #[test]
    fn p3_a_mutated_design_c_token_never_verifies(o in op(), o2 in prop::option::of(op())) {
        let w = world();
        let mut m = apply(base_c().clone(), &o);
        if let Some(o2) = &o2 { m = apply(m, o2); }
        if verify_c(&m, &w.trust, &policy(), Some(&w.rev)).is_ok() {
            prop_assert!(&m == base_c(), "a changed token verified");
        }
    }
}

proptest! {
    #![proptest_config(cfg(20261204))]
    /// The reader and writer: anything accepted is written back to the same bytes (canonical form is a fixed point), nothing panics.
    #[test]
    fn p4_what_the_reader_accepts_is_a_canonical_fixed_point(b in prop::collection::vec(prop::sample::select(b"{}[]\":,0123456789truefalsn abc\\".to_vec()), 0..200)) {
        if let Ok(j) = parse(&b) {
            let w = write(&j);
            prop_assert_eq!(parse(&w).unwrap(), j);
            prop_assert_eq!(write(&parse(&w).unwrap()), w);
        }
    }
}

fn narrowing() -> impl Strategy<Value = Narrowing> {
    (
        prop::option::of(prop::sample::select(vec![
            Tier::T0,
            Tier::T1,
            Tier::T2,
            Tier::T3,
        ])),
        prop::option::of(prop::collection::btree_set(0usize..8, 0..8)),
        prop::option::of(prop::collection::btree_set(0usize..8, 0..8)),
        prop::option::of(0u64..12_000_000),
        prop::option::of(0u64..700),
        prop::option::of(NOW - 150..NOW + 100),
        prop::option::of(NOW - 50..NOW + 3200),
    )
        .prop_map(|(tier, c, a, spend, rate, nb, ex)| Narrowing {
            tier,
            corpora: c.map(|s| s.into_iter().map(corpus).collect()),
            actions: a.map(|s| {
                let mut v: Vec<String> = s
                    .into_iter()
                    .map(|i| {
                        ACTIONS
                            .get(i)
                            .map_or("zzz".to_string(), ToString::to_string)
                    })
                    .collect();
                v.sort();
                v.dedup();
                v
            }),
            spend_cap: spend,
            rate_cap: rate,
            not_before: nb,
            expiry: ex,
        })
}

/// An independent model of the narrowing law (it does not call the library's checker).
fn model_apply(cur: &Claims, n: &Narrowing) -> Option<Claims> {
    let mut next = cur.clone();
    if let Some(t) = n.tier {
        next.tier = t;
    }
    if let Some(c) = &n.corpora {
        next.corpora = c.clone();
    }
    if let Some(a) = &n.actions {
        next.actions = a.clone();
    }
    if let Some(v) = n.spend_cap {
        next.spend_cap = v;
    }
    if let Some(v) = n.rate_cap {
        next.rate_cap = v;
    }
    if let Some(v) = n.not_before {
        next.not_before = v;
    }
    if let Some(v) = n.expiry {
        next.expiry = v;
    }
    let ok = next.tier <= cur.tier
        && next.corpora.iter().all(|c| cur.corpora.contains(c))
        && next.actions.iter().all(|a| cur.actions.contains(a))
        && next.spend_cap <= cur.spend_cap
        && next.rate_cap <= cur.rate_cap
        && next.not_before >= cur.not_before
        && next.expiry <= cur.expiry
        && next.not_before < next.expiry
        && next.actions.windows(2).all(|w| w[0] < w[1])
        && next.corpora.windows(2).all(|w| w[0] < w[1]);
    ok.then_some(next)
}

proptest! {
    #![proptest_config(cfg(20261205))]
    /// T2 (design C): a random sequence of narrowings. The library accepts exactly the narrowings the model accepts; the chain verifies and its
    /// effective claims equal the model's and never exceed the root; the first widening block, signed with the real key, is refused by the verifier.
    #[test]
    fn p5_random_narrowing_chains_never_exceed_the_root(seq in prop::collection::vec(narrowing(), 1..8)) {
        let w = world();
        let root = root_claims();
        let mut wallet: Wallet = issue_c(&w.issuer, &root).unwrap();
        let mut model = root.clone();
        let mut appended = 0usize;
        for n in &seq {
            let expect = model_apply(&model, n);
            match (append_c(&wallet, n), expect) {
                (Ok(next), Some(m)) => { wallet = next; model = m; appended += 1; }
                (Err(_), None) => {
                    let bad = append_c_unchecked(&wallet, n);
                    if bad.token != wallet.token {
                        let r = verify_c(&bad.token, &w.trust, &policy(), Some(&w.rev));
                        prop_assert!(r.is_err(), "a widening block signed with the real key verified: {:?}", n);
                    }
                }
                (Ok(_), None) => prop_assert!(false, "the library accepted a widening block: {:?}", n),
                (Err(e), Some(_)) => prop_assert!(false, "the library refused a valid narrowing: {:?} {:?}", n, e),
            }
        }
        let v = verify_c(&wallet.token, &w.trust, &Policy { now: model.not_before.max(NOW), ..policy() }, Some(&entropa_tokens::empty_revocations(&w.issuer, model.not_before.max(NOW))));
        match v {
            Ok(v) => {
                prop_assert_eq!(&v.claims, &model);
                prop_assert!(model_apply(&root, &Narrowing {
                    tier: Some(v.claims.tier), corpora: Some(v.claims.corpora.clone()), actions: Some(v.claims.actions.clone()),
                    spend_cap: Some(v.claims.spend_cap), rate_cap: Some(v.claims.rate_cap), not_before: Some(v.claims.not_before), expiry: Some(v.claims.expiry),
                }).is_some(), "effective claims exceed the root");
                prop_assert_eq!(v.chain_len, 1 + appended);
            }
            // only a policy refusal (the narrowed window, the TTL cap) may stop a valid chain, never a signature or a widening
            Err(d) => prop_assert!(matches!(d, Deny::NotYetValid | Deny::Expired | Deny::TtlTooLong), "{:?}", d),
        }
    }
}

proptest! {
    #![proptest_config(cfg(20261206))]
    /// B2 controls: random valid claims issue, verify and come back unchanged (design A), and a random valid narrowing chain verifies in C.
    #[test]
    fn p6_valid_tokens_verify_and_round_trip(
        tier in prop::sample::select(vec![Tier::T0, Tier::T1, Tier::T2, Tier::T3]),
        c in prop::collection::btree_set(0usize..8, 0..8), a in prop::collection::btree_set(0usize..6, 0..6),
        spend in any::<u64>(), rate in any::<u64>(), nb in NOW - 500..NOW + 30, ttl in 1u64..3600, id in "[0-9a-f]{32}", subj in "[a-z0-9._-]{1,64}"
    ) {
        let w = world();
        let claims = Claims {
            token_id: id, subject: subj, tier,
            corpora: c.into_iter().map(corpus).collect(), actions: a.into_iter().map(|i| ACTIONS[i].to_string()).collect(),
            spend_cap: spend, rate_cap: rate, not_before: nb, expiry: nb + ttl.max((NOW + 1).saturating_sub(nb)), audience: "node-1".into(), parent: None,
        };
        prop_assume!(claims.expiry - claims.not_before <= 3600);
        let t = issue_a(&w.issuer, &claims).unwrap();
        prop_assert_eq!(verify_a(&t, &w.trust, &policy(), Some(&w.rev), None).unwrap().claims, claims.clone());
        let wc = issue_c(&w.issuer, &claims).unwrap();
        prop_assert_eq!(verify_c(&wc.token, &w.trust, &policy(), Some(&w.rev)).unwrap().claims, claims);
    }
}
