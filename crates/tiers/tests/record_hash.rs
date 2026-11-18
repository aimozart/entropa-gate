//! AT2 task 6 (mutation survivors `request_hash` -> "" and -> "xyzzy"): the request hash in the record is BLAKE3 over the request fields, each prefixed with its length as 8 bytes big-endian,
//! in the order token, parent, action, corpus, tool, cost (8 bytes big-endian), payload, text; an absent parent, corpus or tool is the empty string. The expected value here is computed
//! by this test's own code, and every field must change the hash.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::cedar::CedarPolicy;
use entropa_tiers::{
    EgressGuard, Gate, Guard, Meter, OfflineVerifier, RecordSink, Request, Retrieval, TierRecord,
};
use entropa_tokens::{empty_revocations, Tier, Trust};

struct F;
impl EgressGuard for F {
    fn check(&self, _: Tier, _: &[u8]) -> Result<Guard, String> {
        Ok(Guard::Allow)
    }
}
impl Retrieval for F {
    fn read(&self, _: &str, _: &str) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
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
impl RecordSink for F {
    fn write(&self, _: &TierRecord) -> Result<(), String> {
        Ok(())
    }
}

fn expected(r: &Request) -> String {
    let mut h = blake3::Hasher::new();
    let mut put = |b: &[u8]| {
        h.update(&(b.len() as u64).to_be_bytes());
        h.update(b);
    };
    put(&r.token);
    put(r.parent.as_deref().unwrap_or(&[]));
    put(r.action.as_bytes());
    put(r.corpus.as_deref().unwrap_or("").as_bytes());
    put(r.tool.as_deref().unwrap_or("").as_bytes());
    put(&r.cost.to_be_bytes());
    put(&r.payload);
    put(r.text.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

#[test]
fn h1_the_request_hash_is_the_documented_hash_and_every_field_changes_it() {
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    trust.add(&issuer.pubkey_hex());
    let v = OfflineVerifier {
        trust,
        audience: "node-1".into(),
        skew: 30,
        max_ttl: 3600,
        rev_max_age: 300,
        revocations: Some(empty_revocations(&issuer, 1_800_000_000)),
    };
    let cedar = CedarPolicy::tiers();
    let gate = Gate {
        verifier: &v,
        policy: &cedar,
        egress: &F,
        retrieval: &F,
        meter: &F,
        sink: &F,
    };
    let base = Request {
        token: b"junk".to_vec(),
        parent: Some(b"parent".to_vec()),
        action: "read_corpus".into(),
        corpus: Some("c".repeat(64)),
        tool: Some("tool:x".into()),
        cost: 7,
        payload: b"payload".to_vec(),
        text: "text".into(),
    };
    let h = |r: &Request| gate.decide(r, 1_800_000_000).record.request_hash;
    let b = h(&base);
    assert_eq!(b, expected(&base), "the documented encoding");
    assert_eq!(b.len(), 64);
    assert_eq!(h(&base), b, "stable");
    let mut variants: Vec<Request> = Vec::new();
    let mut v1 = base.clone();
    v1.token = b"junK".to_vec();
    variants.push(v1);
    let mut v2 = base.clone();
    v2.parent = None;
    variants.push(v2);
    let mut v3 = base.clone();
    v3.action = "call_model".into();
    variants.push(v3);
    let mut v4 = base.clone();
    v4.corpus = None;
    variants.push(v4);
    let mut v5 = base.clone();
    v5.tool = Some("tool:y".into());
    variants.push(v5);
    let mut v6 = base.clone();
    v6.cost = 8;
    variants.push(v6);
    let mut v7 = base.clone();
    v7.payload = b"payloaD".to_vec();
    variants.push(v7);
    let mut v8 = base.clone();
    v8.text = "texT".into();
    variants.push(v8);
    for (i, r) in variants.iter().enumerate() {
        let x = h(r);
        assert_ne!(x, b, "variant {i} must change the hash");
        assert_eq!(x, expected(r), "variant {i}");
    }
    // length prefixes: moving a byte between two adjacent fields changes the hash
    let mut a = base.clone();
    a.action = "ab".into();
    a.tool = Some("c".into());
    let mut c = base;
    c.action = "a".into();
    c.tool = Some("bc".into());
    assert_ne!(h(&a), h(&c));
}
