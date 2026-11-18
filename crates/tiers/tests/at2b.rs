//! AT2b red tests (a stage record (not published)): the atomic meter, the gate's reserve/release contract, the egress adapter, the sealed retrieval adapter and the ledger sink, all REAL parts
//! (no fake of the thing under test). Tokens are real and signed. Synthetic data only; secret-shaped strings are built from parts at run time. Against the red stubs every test
//! must fail for the stated reason (the stubs record nothing, answer "not implemented" and the gate does not call `try_reserve` yet).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::adapters::{EgressAdapter, LedgerSink, MemoryMeter, SealedRetrieval};
use entropa_tiers::{
    Action, Decision, DenyCode, EgressGuard, Gate, Guard, Meter, MeterDeny, OfflineVerifier,
    PolicyEngine, RecordSink, Request, Retrieval, TierRecord,
};
use entropa_tokens::{empty_revocations, issue_a, Claims, Tier, Trust};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const NOW: u64 = 1_800_000_000;
const CORPUS: &str = "00000000000000000000000000000000000000000000000000000000000000aa";
const DEST: &str = "https://api.model.example/v1/chat";

// ---------------------------------------------------------------- the meter
#[test]
fn m1_spend_cap_is_recorded_across_calls_and_the_overrun_is_refused() {
    let m = MemoryMeter::new();
    assert_eq!(m.try_reserve("t", 400, 1000, 100, NOW), Ok(()));
    assert_eq!(m.try_reserve("t", 400, 1000, 100, NOW), Ok(()));
    assert_eq!(m.spent("t"), 800, "usage must be recorded");
    assert_eq!(
        m.try_reserve("t", 400, 1000, 100, NOW),
        Err(MeterDeny::Spend),
        "800 + 400 is over 1000"
    );
    assert_eq!(m.spent("t"), 800, "a refused reservation records nothing");
    assert_eq!(
        m.try_reserve("t", 200, 1000, 100, NOW),
        Ok(()),
        "exactly the cap is allowed"
    );
    assert_eq!(m.spent("t"), 1000);
    assert_eq!(m.try_reserve("t", 1, 1000, 100, NOW), Err(MeterDeny::Spend));
}

#[test]
fn m2_rate_cap_is_a_sliding_minute_and_tokens_do_not_share_usage() {
    let m = MemoryMeter::new();
    for _ in 0..3 {
        assert_eq!(m.try_reserve("a", 0, 10, 3, NOW), Ok(()));
    }
    assert_eq!(m.try_reserve("a", 0, 10, 3, NOW), Err(MeterDeny::Rate));
    assert_eq!(m.calls_last_minute("a", NOW), 3);
    assert_eq!(
        m.try_reserve("a", 0, 10, 3, NOW + 59),
        Err(MeterDeny::Rate),
        "59 s later the calls are still inside the minute"
    );
    assert_eq!(
        m.try_reserve("a", 0, 10, 3, NOW + 60),
        Ok(()),
        "60 s later they have left the window"
    );
    assert_eq!(m.try_reserve("b", 0, 10, 3, NOW), Ok(()), "another token");
    assert_eq!(m.spent("b"), 0);
}

#[test]
fn m3_release_gives_the_reservation_back() {
    let m = MemoryMeter::new();
    assert_eq!(m.try_reserve("t", 600, 1000, 2, NOW), Ok(()));
    assert_eq!(m.try_reserve("t", 300, 1000, 2, NOW), Ok(()));
    assert_eq!(m.try_reserve("t", 1, 1000, 2, NOW), Err(MeterDeny::Rate));
    m.release("t", 300, NOW);
    assert_eq!(m.spent("t"), 600);
    assert_eq!(m.calls_last_minute("t", NOW), 1);
    assert_eq!(m.try_reserve("t", 400, 1000, 2, NOW), Ok(()));
    m.release("t", 400, NOW);
    m.release("t", 600, NOW);
    m.release("t", 600, NOW); // a double release must not underflow
    assert_eq!(m.spent("t"), 0);
    assert_eq!(m.calls_last_minute("t", NOW), 0);
}

fn hammer(threads: usize, spend: bool) -> u64 {
    let (cap, attempts) = (50u64, 1000u64);
    let m = Arc::new(MemoryMeter::new());
    let admitted = Arc::new(AtomicU64::new(0));
    let hs: Vec<_> = (0..threads)
        .map(|_| {
            let (m, adm) = (m.clone(), admitted.clone());
            std::thread::spawn(move || {
                for _ in 0..attempts / threads as u64 {
                    let r = if spend {
                        m.try_reserve("t", 1, cap, u64::MAX, NOW)
                    } else {
                        m.try_reserve("t", 0, u64::MAX, cap, NOW)
                    };
                    if r.is_ok() {
                        adm.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    admitted.load(Ordering::SeqCst)
}

#[test]
fn m4_concurrent_callers_never_overrun_a_cap_and_the_cap_is_reached() {
    // 2, 4 and 8 threads, 200 repetitions of 1,000 attempts against a cap of 50: admitted is EXACTLY the cap (never over; never under, nothing is released)
    for threads in [2usize, 4, 8] {
        for spend in [true, false] {
            let mut overruns = 0;
            for _ in 0..200 {
                let n = hammer(threads, spend);
                if n > 50 {
                    overruns += 1;
                }
                assert_eq!(n, 50, "threads {threads} spend {spend}: admitted {n}");
            }
            assert_eq!(overruns, 0);
        }
    }
}

// ----------------------------------------------------- the gate's contract
struct Allow;
impl PolicyEngine for Allow {
    fn allows(&self, _: Tier, _: Action, _: Option<&str>) -> Result<bool, String> {
        Ok(true)
    }
    fn policy_hash(&self) -> String {
        "p".repeat(64)
    }
}
struct Deny(Result<bool, String>);
impl PolicyEngine for Deny {
    fn allows(&self, _: Tier, _: Action, _: Option<&str>) -> Result<bool, String> {
        self.0.clone()
    }
    fn policy_hash(&self) -> String {
        "p".repeat(64)
    }
}
struct Panics;
impl PolicyEngine for Panics {
    fn allows(&self, _: Tier, _: Action, _: Option<&str>) -> Result<bool, String> {
        panic!("engine blew up");
    }
    fn policy_hash(&self) -> String {
        "p".repeat(64)
    }
}
struct Fixed(Result<Guard, String>);
impl EgressGuard for Fixed {
    fn check(&self, _: Tier, _: &[u8]) -> Result<Guard, String> {
        self.0.clone()
    }
}
struct Reads(Result<Vec<u8>, String>);
impl Retrieval for Reads {
    fn read(&self, _: &str, _: &str) -> Result<Vec<u8>, String> {
        self.0.clone()
    }
}
/// A meter that counts reserve and release calls on top of the real one.
struct Counting {
    inner: MemoryMeter,
    reserved: Mutex<Vec<(u64, u64)>>,
    released: Mutex<Vec<(u64, u64)>>,
}
impl Counting {
    fn new() -> Self {
        Counting {
            inner: MemoryMeter::new(),
            reserved: Mutex::new(vec![]),
            released: Mutex::new(vec![]),
        }
    }
}
impl Meter for Counting {
    fn spent(&self, t: &str) -> u64 {
        self.inner.spent(t)
    }
    fn calls_last_minute(&self, t: &str, n: u64) -> u64 {
        self.inner.calls_last_minute(t, n)
    }
    fn try_reserve(&self, t: &str, c: u64, s: u64, r: u64, n: u64) -> Result<(), MeterDeny> {
        self.reserved.lock().unwrap().push((c, n));
        self.inner.try_reserve(t, c, s, r, n)
    }
    fn release(&self, t: &str, c: u64, n: u64) {
        self.released.lock().unwrap().push((c, n));
        self.inner.release(t, c, n)
    }
}
struct Sink {
    fail: bool,
    n: RefCell<u32>,
}
impl RecordSink for Sink {
    fn write(&self, _: &TierRecord) -> Result<(), String> {
        if self.fail {
            return Err("disk full".into());
        }
        *self.n.borrow_mut() += 1;
        Ok(())
    }
}

struct Keys {
    issuer: Probe,
    verifier: OfflineVerifier,
}
fn keys() -> Keys {
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    assert!(!trust.add(&issuer.pubkey_hex()).is_empty());
    let list = empty_revocations(&issuer, NOW);
    Keys {
        verifier: OfflineVerifier {
            trust,
            audience: "node-1".into(),
            skew: 30,
            max_ttl: 3600,
            rev_max_age: 300,
            revocations: Some(list),
        },
        issuer,
    }
}
fn claims(id: u64, tier: Tier) -> Claims {
    Claims {
        token_id: format!("{id:032x}"),
        subject: "subject-1".into(),
        tier,
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
    }
}
fn req(token: Vec<u8>, action: &str, cost: u64) -> Request {
    Request {
        token,
        action: action.into(),
        corpus: Some(CORPUS.into()),
        tool: Some("tool:search".into()),
        cost,
        payload: b"hello".to_vec(),
        text: "question".into(),
        ..Request::default()
    }
}

#[test]
fn g1_an_allowed_call_records_its_usage_and_is_never_released() {
    let k = keys();
    let meter = Counting::new();
    let sink = Sink {
        fail: false,
        n: RefCell::new(0),
    };
    let gate = Gate {
        verifier: &k.verifier,
        policy: &Allow,
        egress: &Fixed(Ok(Guard::Allow)),
        retrieval: &Reads(Ok(b"a".to_vec())),
        meter: &meter,
        sink: &sink,
    };
    let t = issue_a(&k.issuer, &claims(1, Tier::T1)).unwrap();
    let o = gate.decide(&req(t, "call_model", 300), NOW);
    assert_eq!(o.decision, Decision::Allowed);
    assert_eq!(meter.reserved.lock().unwrap().len(), 1, "one reservation");
    assert!(meter.released.lock().unwrap().is_empty(), "no release");
    assert_eq!(meter.spent(&format!("{:032x}", 1)), 300);
}

#[test]
fn g2_the_spend_cap_holds_across_calls_through_the_gate() {
    let k = keys();
    let meter = MemoryMeter::new();
    let sink = Sink {
        fail: false,
        n: RefCell::new(0),
    };
    let gate = Gate {
        verifier: &k.verifier,
        policy: &Allow,
        egress: &Fixed(Ok(Guard::Allow)),
        retrieval: &Reads(Ok(b"a".to_vec())),
        meter: &meter,
        sink: &sink,
    };
    let t = issue_a(&k.issuer, &claims(2, Tier::T1)).unwrap(); // spend cap 1000
    for _ in 0..2 {
        assert_eq!(
            gate.decide(&req(t.clone(), "call_model", 400), NOW)
                .decision,
            Decision::Allowed
        );
    }
    assert_eq!(
        gate.decide(&req(t, "call_model", 400), NOW).decision,
        Decision::Denied(DenyCode::SpendCap),
        "usage must accumulate across calls: 800 + 400 > 1000"
    );
}

#[test]
#[allow(clippy::type_complexity)]
fn g3_every_later_denial_gives_the_reservation_back() {
    let k = keys();
    let cases: Vec<(&str, DenyCode, Box<dyn Fn(&mut Setup)>)> = vec![
        (
            "policy denied",
            DenyCode::PolicyDenied,
            Box::new(|s| s.deny = Some(Ok(false))),
        ),
        (
            "policy error",
            DenyCode::PolicyError,
            Box::new(|s| s.deny = Some(Err("x".into()))),
        ),
        (
            "egress blocked",
            DenyCode::EgressBlocked,
            Box::new(|s| s.egress = Ok(Guard::Block)),
        ),
        (
            "egress error",
            DenyCode::EgressError,
            Box::new(|s| s.egress = Err("x".into())),
        ),
        (
            "record failed",
            DenyCode::RecordFailed,
            Box::new(|s| s.sink_fail = true),
        ),
    ];
    for (name, want, tweak) in cases {
        let mut s = Setup::default();
        tweak(&mut s);
        let meter = Counting::new();
        let sink = Sink {
            fail: s.sink_fail,
            n: RefCell::new(0),
        };
        let deny = Deny(s.deny.clone().unwrap_or(Ok(true)));
        let eg = Fixed(s.egress.clone());
        let gate = Gate {
            verifier: &k.verifier,
            policy: &deny,
            egress: &eg,
            retrieval: &Reads(Ok(b"a".to_vec())),
            meter: &meter,
            sink: &sink,
        };
        let t = issue_a(&k.issuer, &claims(3, Tier::T1)).unwrap();
        let o = gate.decide(&req(t, "call_model", 300), NOW);
        assert_eq!(o.decision, Decision::Denied(want), "{name}");
        assert_eq!(meter.reserved.lock().unwrap().len(), 1, "{name}: reserved");
        assert_eq!(meter.released.lock().unwrap().len(), 1, "{name}: released");
        assert_eq!(
            meter.spent(&format!("{:032x}", 3)),
            0,
            "{name}: usage back to 0"
        );
        assert_eq!(
            meter.calls_last_minute(&format!("{:032x}", 3), NOW),
            0,
            "{name}"
        );
    }
}
struct Setup {
    deny: Option<Result<bool, String>>,
    egress: Result<Guard, String>,
    sink_fail: bool,
}
impl Default for Setup {
    fn default() -> Self {
        Setup {
            deny: None,
            egress: Ok(Guard::Allow),
            sink_fail: false,
        }
    }
}

#[test]
fn g4_a_retrieval_error_gives_the_reservation_back() {
    let k = keys();
    let meter = Counting::new();
    let sink = Sink {
        fail: false,
        n: RefCell::new(0),
    };
    let gate = Gate {
        verifier: &k.verifier,
        policy: &Allow,
        egress: &Fixed(Ok(Guard::Allow)),
        retrieval: &Reads(Err("no such corpus".into())),
        meter: &meter,
        sink: &sink,
    };
    let t = issue_a(&k.issuer, &claims(4, Tier::T0)).unwrap();
    let o = gate.decide(&req(t, "read_corpus", 50), NOW);
    assert_eq!(o.decision, Decision::Denied(DenyCode::RetrievalError));
    assert_eq!(meter.released.lock().unwrap().len(), 1);
    assert_eq!(meter.spent(&format!("{:032x}", 4)), 0);
}

#[test]
fn g5_a_denial_before_the_limits_step_never_reserves() {
    let k = keys();
    let meter = Counting::new();
    let sink = Sink {
        fail: false,
        n: RefCell::new(0),
    };
    let gate = Gate {
        verifier: &k.verifier,
        policy: &Allow,
        egress: &Fixed(Ok(Guard::Allow)),
        retrieval: &Reads(Ok(b"a".to_vec())),
        meter: &meter,
        sink: &sink,
    };
    let t = issue_a(&k.issuer, &claims(5, Tier::T0)).unwrap();
    // T0 may not call a model: refused at the tier ceiling, before any reservation
    assert_eq!(
        gate.decide(&req(t, "call_model", 10), NOW).decision,
        Decision::Denied(DenyCode::TierForbids)
    );
    assert!(meter.reserved.lock().unwrap().is_empty());
    assert!(meter.released.lock().unwrap().is_empty());
    // a garbage token: refused at step 1
    assert!(matches!(
        gate.decide(&req(b"junk".to_vec(), "read_corpus", 10), NOW)
            .decision,
        Decision::Denied(DenyCode::Token(_))
    ));
    assert!(meter.reserved.lock().unwrap().is_empty());
}

#[test]
fn g6_a_panic_after_the_reservation_is_a_denial_and_the_reservation_is_released() {
    let k = keys();
    let meter = Counting::new();
    let sink = Sink {
        fail: false,
        n: RefCell::new(0),
    };
    let gate = Gate {
        verifier: &k.verifier,
        policy: &Panics,
        egress: &Fixed(Ok(Guard::Allow)),
        retrieval: &Reads(Ok(b"a".to_vec())),
        meter: &meter,
        sink: &sink,
    };
    let t = issue_a(&k.issuer, &claims(6, Tier::T1)).unwrap();
    let o = gate.decide(&req(t, "call_model", 300), NOW);
    assert_eq!(o.decision, Decision::Denied(DenyCode::InternalError));
    assert!(o.answer.is_none());
    assert_eq!(meter.released.lock().unwrap().len(), 1, "released");
    assert_eq!(meter.spent(&format!("{:032x}", 6)), 0);
    assert_eq!(*sink.n.borrow(), 1, "the denial itself is recorded once");
}

// ------------------------------------------------------- the egress adapter
fn egress(dest: &str) -> EgressAdapter {
    let policy = entropa_egress::eval::load_policy(&entropa_egress::eval::policy_from_extra(
        &serde_json::json!({}),
    ))
    .unwrap();
    EgressAdapter::new(policy, dest, b"adapter-test-key")
}

#[test]
fn e1_clean_text_is_allowed_at_t1() {
    let g = egress(DEST);
    assert_eq!(
        g.check(Tier::T1, b"Summarise the retention rules for audit logs."),
        Ok(Guard::Allow)
    );
}

#[test]
fn e2_a_planted_key_is_blocked_plain_json_nested_and_after_multibyte_text() {
    let g = egress(DEST);
    let key = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
    let plain = format!("please use {key} to log in");
    assert_eq!(g.check(Tier::T1, plain.as_bytes()), Ok(Guard::Block));
    let nested = format!("{{\"a\":{{\"b\":[\"x\",\"{key}\"]}}}}");
    assert_eq!(g.check(Tier::T2, nested.as_bytes()), Ok(Guard::Block));
    let multibyte = format!("héllo wörld 日本語 ✓ {key} ünïcode");
    assert_eq!(g.check(Tier::T1, multibyte.as_bytes()), Ok(Guard::Block));
}

#[test]
fn e3_a_redact_outcome_is_a_block_at_the_gate() {
    // an email address on a reserved invalid domain is personal data: the egress guard answers Redact, the adapter must answer Block
    let g = egress(DEST);
    let body = "contact alice.sample@example.invalid about the file";
    assert_eq!(g.check(Tier::T1, body.as_bytes()), Ok(Guard::Block));
}

#[test]
fn e4_t0_wrong_destination_oversize_and_invalid_input_never_allow() {
    assert_eq!(
        egress(DEST).check(Tier::T0, b"clean text"),
        Ok(Guard::Block),
        "T0 has no egress"
    );
    assert_ne!(
        egress("https://evil.example/collect").check(Tier::T1, b"clean text"),
        Ok(Guard::Allow),
        "a destination that is not on the policy"
    );
    let big = vec![b'a'; 64 * 1024 + 1];
    assert_ne!(egress(DEST).check(Tier::T1, &big), Ok(Guard::Allow));
    assert_ne!(
        egress(DEST).check(Tier::T1, &[0xff, 0xfe, 0x00, 0x41]),
        Ok(Guard::Allow),
        "bytes that are not text"
    );
}

#[test]
fn e5_through_the_gate_a_blocked_payload_is_egress_blocked_and_released() {
    let k = keys();
    let meter = Counting::new();
    let sink = Sink {
        fail: false,
        n: RefCell::new(0),
    };
    let eg = egress(DEST);
    let gate = Gate {
        verifier: &k.verifier,
        policy: &Allow,
        egress: &eg,
        retrieval: &Reads(Ok(b"a".to_vec())),
        meter: &meter,
        sink: &sink,
    };
    let t = issue_a(&k.issuer, &claims(7, Tier::T1)).unwrap();
    let mut r = req(t.clone(), "call_model", 100);
    r.payload = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP").into_bytes();
    assert_eq!(
        gate.decide(&r, NOW).decision,
        Decision::Denied(DenyCode::EgressBlocked)
    );
    assert_eq!(meter.spent(&format!("{:032x}", 7)), 0);
    let mut ok = req(t, "call_model", 100);
    ok.payload = b"Summarise the retention rules.".to_vec();
    assert_eq!(gate.decide(&ok, NOW).decision, Decision::Allowed);
}

// ------------------------------------------------------ the retrieval adapter
fn clause(std: &str, id: &str, text: &str) -> entropa_standards::corpus::Clause {
    entropa_standards::corpus::Clause {
        standard: std.into(),
        std_version: "1".into(),
        id: id.into(),
        tier: entropa_standards::corpus::Tier::Open,
        text: text.into(),
        text_sha256: hex_sha(text),
    }
}
fn hex_sha(t: &str) -> String {
    entropa_standards::corpus::text_sha256(t)
}
fn retriever() -> (SealedRetrieval, String, String) {
    let h1 = "1".repeat(64);
    let h2 = "2".repeat(64);
    let c1 = vec![
        clause("SYN-STD", "SYN-1", "Audit records shall be protected from unauthorised modification and deletion by cryptographic means."),
        clause("SYN-STD", "SYN-2", "Access to the audit store shall be limited to named roles and reviewed every quarter."),
    ];
    let c2 = vec![clause(
        "SYN-STD",
        "SYN-9",
        "Zebra migration corridors shall be mapped annually.",
    )];
    let mut r = entropa_standards::retrieve::Retriever::from_clauses("v1", &h1, c1);
    r.add_clauses("v2", &h2, c2);
    (SealedRetrieval::new(r), h1, h2)
}

#[test]
fn r1_a_held_corpus_hash_is_searched_and_only_that_version() {
    let (r, h1, h2) = retriever();
    let a = String::from_utf8(
        r.read(&h1, "audit records protected from modification")
            .unwrap(),
    )
    .unwrap();
    assert!(a.contains("SYN-1"), "{a}");
    assert!(!a.contains("SYN-9"), "never the other version");
    let b = String::from_utf8(r.read(&h2, "zebra migration corridors").unwrap()).unwrap();
    assert!(b.contains("SYN-9"));
    assert!(!b.contains("SYN-1"));
}

#[test]
fn r2_an_unknown_short_or_uppercase_hash_is_an_error_not_a_default() {
    let (r, h1, _) = retriever();
    for bad in [
        "3".repeat(64),
        "".to_string(),
        "1".repeat(63),
        h1.to_uppercase().replace('1', "A"),
        format!("{h1} "),
        "../../etc".to_string(),
    ] {
        assert!(r.read(&bad, "audit records").is_err(), "{bad:?}");
    }
}

#[test]
fn r3_an_abstention_is_a_normal_answer_that_says_so() {
    let (r, h1, _) = retriever();
    let a = r.read(&h1, "quantum banana fishing licence").unwrap();
    let text = String::from_utf8(a).unwrap();
    assert!(
        text.contains("not_in_corpus") || text.contains("NotInCorpus"),
        "{text}"
    );
}

#[test]
fn r4_passages_are_marked_untrusted() {
    let (r, h1, _) = retriever();
    let text = String::from_utf8(
        r.read(&h1, "audit records protected from modification")
            .unwrap(),
    )
    .unwrap();
    assert!(text.contains("\"untrusted\":true"), "{text}");
}

// ------------------------------------------------------------- the ledger sink
struct TestNode {
    dir: std::path::PathBuf,
    pubkey: String,
}
/// A node directory and a signer. The key seed is derived at run time from the tag (a test key, never stored).
fn node(tag: &str) -> (TestNode, Probe) {
    let dir = std::env::temp_dir().join(format!("at2b-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("evidence-ledger")).unwrap();
    let p = probe(tag);
    (
        TestNode {
            pubkey: p.pubkey_hex(),
            dir,
        },
        p,
    )
}
fn probe(tag: &str) -> Probe {
    let seed = hex::encode(blake3::hash(format!("at2b-test-key-{tag}").as_bytes()).as_bytes());
    Probe::from_signing_key_hex(&seed).unwrap()
}
fn record(allow: bool, reason: &str) -> TierRecord {
    TierRecord {
        label: if allow { "token_used" } else { "token_denied" },
        decision: if allow { "allowed" } else { "denied" },
        reason: reason.into(),
        tier: Some("T1"),
        action: "call_model",
        token_hash: Some("a".repeat(64)),
        request_hash: "b".repeat(64),
        policy_hash: "c".repeat(64),
        ts: NOW,
    }
}

#[test]
fn l1_records_are_appended_signed_and_verify_with_the_platinum_verifier() {
    let (n, probe) = node("l1");
    let sink = LedgerSink::new(n.dir.clone(), Box::new(probe));
    sink.write(&record(true, "allowed")).unwrap();
    sink.write(&record(false, "egress_blocked")).unwrap();
    let out = entropa_platinum::verify_evidence_with(&n.dir, &n.pubkey).unwrap();
    assert!(out.contains("records=2"), "{out}");
}

#[test]
fn l2_every_denial_word_maps_to_the_closed_vocabulary_and_is_accepted() {
    let (n, probe) = node("l2");
    let sink = LedgerSink::new(n.dir.clone(), Box::new(probe));
    let words = [
        "expired",
        "unknown_action",
        "tier_forbids",
        "corpus_not_in_token",
        "action_not_in_token",
        "spend_cap",
        "rate_cap",
        "policy_denied",
        "policy_error",
        "egress_blocked",
        "egress_error",
        "retrieval_error",
        "record_failed",
        "internal_error",
        "bad_signature",
        "revoked",
    ];
    for w in words {
        sink.write(&record(false, w))
            .unwrap_or_else(|e| panic!("{w}: {e}"));
    }
    let out = entropa_platinum::verify_evidence_with(&n.dir, &n.pubkey).unwrap();
    assert!(out.contains(&format!("records={}", words.len())), "{out}");
}

struct Failing(Probe);
impl entropa_core::CheckpointSigner for Failing {
    fn algorithm(&self) -> &'static str {
        self.0.algorithm()
    }
    fn pubkey_hex(&self) -> String {
        self.0.pubkey_hex()
    }
    fn try_sign_hex(&self, _: &[u8]) -> Result<String, entropa_core::SignError> {
        Err(entropa_core::SignError::Backend("signer down".into()))
    }
}

#[test]
fn l3_a_failing_signer_writes_nothing_and_the_ledger_still_verifies() {
    let (n, p3) = node("l3");
    let good = LedgerSink::new(n.dir.clone(), Box::new(probe("l3")));
    good.write(&record(true, "allowed")).unwrap();
    let bad = LedgerSink::new(n.dir.clone(), Box::new(Failing(p3)));
    assert!(bad.write(&record(false, "policy_denied")).is_err());
    let out = entropa_platinum::verify_evidence_with(&n.dir, &n.pubkey).unwrap();
    assert!(out.contains("records=1"), "{out}");
}

// ---------------------------------------------------- wiring: all real parts
#[test]
fn w1_control_300_valid_requests_through_the_real_parts_one_verifying_record_each() {
    let k = keys();
    let (n, probe) = node("w1");
    let sink = LedgerSink::new(n.dir.clone(), Box::new(probe));
    let meter = MemoryMeter::new();
    let eg = egress(DEST);
    let (ret, h1, _) = retriever();
    let mut c = claims(8, Tier::T1);
    c.corpora = vec![h1.clone()];
    c.spend_cap = 1_000_000;
    c.rate_cap = 100_000;
    let t = issue_a(&k.issuer, &c).unwrap();
    let gate = Gate {
        verifier: &k.verifier,
        policy: &Allow,
        egress: &eg,
        retrieval: &ret,
        meter: &meter,
        sink: &sink,
    };
    for i in 0..300u64 {
        let mut r = req(
            t.clone(),
            if i % 2 == 0 {
                "call_model"
            } else {
                "read_corpus"
            },
            1,
        );
        r.corpus = Some(h1.clone());
        r.payload = format!("Summarise item {i} of the retention rules.").into_bytes();
        r.text = "audit records protected from modification".into();
        let o = gate.decide(&r, NOW);
        assert_eq!(o.decision, Decision::Allowed, "request {i}");
    }
    let out = entropa_platinum::verify_evidence_with(&n.dir, &n.pubkey).unwrap();
    assert!(out.contains("records=300"), "{out}");
    assert_eq!(meter.spent(&format!("{:032x}", 8)), 300);
}

#[test]
fn w2_attacks_through_the_real_parts_are_denied_and_each_leaves_one_record() {
    let k = keys();
    let (n, probe) = node("w2");
    let sink = LedgerSink::new(n.dir.clone(), Box::new(probe));
    let meter = MemoryMeter::new();
    let eg = egress(DEST);
    let (ret, h1, _) = retriever();
    let mut c = claims(9, Tier::T1);
    c.corpora = vec![h1.clone()];
    let t = issue_a(&k.issuer, &c).unwrap();
    let gate = Gate {
        verifier: &k.verifier,
        policy: &Allow,
        egress: &eg,
        retrieval: &ret,
        meter: &meter,
        sink: &sink,
    };
    let key = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
    let mut a = req(t.clone(), "call_model", 1);
    a.payload = key.clone().into_bytes();
    let mut b = req(t.clone(), "call_tool", 1); // T1 may not call a tool
    b.payload = b"x".to_vec();
    let mut d = req(t.clone(), "read_corpus", 1);
    d.corpus = Some("3".repeat(64)); // not in the token
    let mut e = req(t, "call_model", 5000); // over the spend cap
    e.payload = b"clean".to_vec();
    let want = [
        DenyCode::EgressBlocked,
        DenyCode::TierForbids,
        DenyCode::CorpusNotInToken,
        DenyCode::SpendCap,
    ];
    for (r, w) in [a, b, d, e].iter().zip(want) {
        let o = gate.decide(r, NOW);
        assert_eq!(o.decision, Decision::Denied(w));
        assert!(o.answer.is_none());
    }
    let out = entropa_platinum::verify_evidence_with(&n.dir, &n.pubkey).unwrap();
    assert!(out.contains("records=4"), "{out}");
    assert_eq!(meter.spent(&format!("{:032x}", 9)), 0, "nothing was used");
}
