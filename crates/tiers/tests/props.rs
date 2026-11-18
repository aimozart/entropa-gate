//! AT2 task 6: properties on hostile and multibyte input, 20,000 seeded cases (AT2_CASES overrides): `decide` never panics; it writes exactly one record per decision; a request with a
//! token that is not byte-for-byte a valid one is NEVER allowed (a flipped bit, a truncation, an appended byte, a swapped signature, random bytes, empty); the record never contains any
//! of the request text; the same request gives the same outcome twice. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::cedar::CedarPolicy;
use entropa_tiers::{
    Decision, EgressGuard, Gate, Guard, Meter, OfflineVerifier, RecordSink, Request, Retrieval,
    TierRecord,
};
use entropa_tokens::{empty_revocations, issue_a, Claims, Tier, Trust};
use std::cell::RefCell;

const NOW: u64 = 1_800_000_000;
const CORPUS: &str = "00000000000000000000000000000000000000000000000000000000000000aa";
struct F;
impl EgressGuard for F {
    fn check(&self, _: Tier, _: &[u8]) -> Result<Guard, String> {
        Ok(Guard::Allow)
    }
}
impl Retrieval for F {
    fn read(&self, _: &str, _: &str) -> Result<Vec<u8>, String> {
        Ok(b"a".to_vec())
    }
}
impl Meter for F {
    fn spent(&self, _: &str) -> u64 {
        0
    }
    fn calls_last_minute(&self, _: &str, _: u64) -> u64 {
        0
    }
}
struct Count(RefCell<u64>);
impl RecordSink for Count {
    fn write(&self, _: &TierRecord) -> Result<(), String> {
        *self.0.borrow_mut() += 1;
        Ok(())
    }
}
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

const PIECES: &[&str] = &[
    "a",
    "Z",
    "0",
    "é",
    "\u{212a}",
    "\u{17f}",
    "\u{435}",
    "\u{1f600}",
    "\u{200d}",
    "-",
    "_",
    ":",
    ".",
    " ",
    "\"",
    "\\",
    "\u{0}",
    "tool:search",
    "read_corpus",
    "call_model",
    "tier t3",
    "Bearer ",
    "{",
    "}",
];

#[test]
fn p1_hostile_requests_never_panic_and_a_changed_token_is_never_allowed() {
    let cases: usize = std::env::var("AT2_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    trust.add(&issuer.pubkey_hex());
    let v = OfflineVerifier {
        trust,
        audience: "node-1".into(),
        skew: 30,
        max_ttl: 3600,
        rev_max_age: 300,
        revocations: Some(empty_revocations(&issuer, NOW)),
    };
    let cedar = CedarPolicy::tiers();
    let sink = Count(RefCell::new(0));
    let gate = Gate {
        verifier: &v,
        policy: &cedar,
        egress: &F,
        retrieval: &F,
        meter: &F,
        sink: &sink,
    };
    let valid: Vec<Vec<u8>> = [Tier::T0, Tier::T1, Tier::T2]
        .iter()
        .enumerate()
        .map(|(i, t)| {
            issue_a(
                &issuer,
                &Claims {
                    token_id: format!("{:032x}", i + 1),
                    subject: "s".into(),
                    tier: *t,
                    corpora: vec![CORPUS.into()],
                    actions: vec![
                        "call_model".into(),
                        "call_tool".into(),
                        "read_corpus".into(),
                        "tool:search".into(),
                    ],
                    spend_cap: 1000,
                    rate_cap: 10,
                    not_before: NOW - 10,
                    expiry: NOW + 600,
                    audience: "node-1".into(),
                    parent: None,
                },
            )
            .unwrap()
        })
        .collect();
    let mut g = Lcg(20261215);
    let text = |g: &mut Lcg| -> String {
        (0..(1 + g.next() % 10))
            .map(|_| PIECES[(g.next() as usize) % PIECES.len()])
            .collect()
    };
    let mut allowed_with_changed_token = 0;
    for i in 0..cases {
        let base = valid[i % 3].clone();
        let (token, changed) = match g.next() % 7 {
            0 => (base, false),
            1 => {
                let mut b = base;
                let at = (g.next() as usize) % b.len();
                b[at] ^= 1 << (g.next() % 8);
                (b, true)
            }
            2 => {
                let mut b = base;
                b.truncate((g.next() as usize) % b.len());
                (b, true)
            }
            3 => {
                let mut b = base;
                b.push((g.next() % 256) as u8);
                (b, true)
            }
            4 => (
                (0..(g.next() % 400))
                    .map(|_| (g.next() % 256) as u8)
                    .collect(),
                true,
            ),
            5 => (Vec::new(), true),
            _ => (text(&mut g).into_bytes(), true),
        };
        let r = Request {
            token,
            parent: None,
            action: ["read_corpus", "call_model", "call_tool"][i % 3].to_string(),
            corpus: Some(CORPUS.into()),
            tool: Some(text(&mut g)),
            cost: g.next() % 5,
            payload: text(&mut g).into_bytes(),
            text: format!("zq9-{}", text(&mut g)),
        };
        let before = *sink.0.borrow();
        let a = gate.decide(&r, NOW);
        assert_eq!(*sink.0.borrow(), before + 1, "case {i}: exactly one record");
        let b = gate.decide(&r, NOW);
        assert_eq!(a, b, "case {i}: deterministic");
        if changed && a.decision == Decision::Allowed {
            allowed_with_changed_token += 1;
        }
        {
            assert!(
                !format!("{:?}", a.record).contains(&r.text),
                "case {i}: request text in a record"
            );
        }
    }
    assert_eq!(
        allowed_with_changed_token, 0,
        "a token that is not byte-for-byte valid was accepted"
    );
}
