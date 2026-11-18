//! AT1 task 3: the planted-attack battery. Twelve attack classes, each with at least 300 generated cases per design (the order asks for 200),
//! both designs, fixed seed. A case that is ACCEPTED is a failure. Controls (valid tokens, and the boundary values that must be accepted) run
//! beside the attacks so a verifier that refuses everything cannot pass. Counts and rule-of-three 95 percent upper bounds are printed and, with
//! AT1_EVIDENCE=path, written as JSON. Keys are throwaway keys made here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tokens::canon::{parse, write, Json};
use entropa_tokens::testing::{append_c_unchecked, append_c_with_key};
use entropa_tokens::{
    append_c, issue_a, issue_c, issue_revocations, narrow_a, verify_a, verify_c, Claims, Deny,
    Narrowing, Policy, Reason, Tier, Trust, Wallet,
};
use std::collections::BTreeMap;

const NOW: u64 = 1_800_000_000;
const N: usize = 300;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
    fn hex(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b"0123456789abcdef"[self.below(16)]))
            .collect()
    }
}

fn corpus(i: usize) -> String {
    format!("{:02x}", i + 0x10).repeat(32)
}
fn claims(rng: &mut Rng) -> Claims {
    Claims {
        token_id: rng.hex(32),
        subject: format!("agent-{}", rng.below(1000)),
        tier: *rng.pick(&[Tier::T1, Tier::T2, Tier::T3]),
        corpora: (0..4).map(corpus).collect(),
        actions: ["cite_check", "lookup_clause", "search", "write"]
            .iter()
            .map(ToString::to_string)
            .collect(),
        spend_cap: 1_000_000 + rng.below(1_000_000) as u64,
        rate_cap: 60 + rng.below(100) as u64,
        not_before: NOW - 100 - rng.below(100) as u64,
        expiry: NOW + 600 + rng.below(1000) as u64,
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
    other_trusted: Probe,
    untrusted: Probe,
    trust: Trust,
    rev: Vec<u8>,
}
fn world() -> World {
    let issuer = Probe::spawn();
    let other_trusted = Probe::spawn();
    let untrusted = Probe::spawn();
    let mut trust = Trust::default();
    trust.add(&issuer.pubkey_hex());
    trust.add(&other_trusted.pubkey_hex());
    let rev = entropa_tokens::empty_revocations(&issuer, NOW);
    World {
        issuer,
        other_trusted,
        untrusted,
        trust,
        rev,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Design {
    A,
    C,
}
struct Tally {
    n: usize,
    accepted: usize,
    reasons: BTreeMap<&'static str, usize>,
}
#[derive(Default)]
struct Report {
    rows: BTreeMap<(String, Design), Tally>,
    controls: BTreeMap<(String, Design), (usize, usize)>,
}
impl Report {
    fn attack(&mut self, class: &str, d: Design, r: Result<(), Deny>) {
        let t = self.rows.entry((class.to_string(), d)).or_insert(Tally {
            n: 0,
            accepted: 0,
            reasons: BTreeMap::new(),
        });
        t.n += 1;
        match r {
            Ok(()) => t.accepted += 1,
            Err(e) => *t.reasons.entry(e.as_str()).or_default() += 1,
        }
    }
    fn control(&mut self, class: &str, d: Design, accepted: bool) {
        let e = self.controls.entry((class.to_string(), d)).or_default();
        e.0 += 1;
        e.1 += usize::from(accepted);
    }
}

fn run(
    d: Design,
    bytes: &[u8],
    w: &World,
    p: &Policy,
    rev: Option<&[u8]>,
    parent: Option<&[u8]>,
) -> Result<(), Deny> {
    match d {
        Design::A => verify_a(bytes, &w.trust, p, rev, parent).map(|_| ()),
        Design::C => verify_c(bytes, &w.trust, p, rev).map(|_| ()),
    }
}
fn make(d: Design, w: &World, c: &Claims) -> Vec<u8> {
    match d {
        Design::A => issue_a(&w.issuer, c).unwrap(),
        Design::C => issue_c(&w.issuer, c).unwrap().token,
    }
}
/// A design C token with 0 to 3 appended narrowing blocks.
fn make_chain(w: &World, c: &Claims, rng: &mut Rng) -> Wallet {
    let mut wal = issue_c(&w.issuer, c).unwrap();
    let mut cap = c.spend_cap;
    for _ in 0..rng.below(3) {
        cap -= 1 + rng.below(100) as u64; // strictly decreasing, so every block narrows
        let n = Narrowing {
            spend_cap: Some(cap),
            ..Narrowing::default()
        };
        wal = append_c(&wal, &n).unwrap();
    }
    wal
}
fn token(d: Design, w: &World, rng: &mut Rng) -> (Vec<u8>, Claims) {
    let c = claims(rng);
    match d {
        Design::A => (issue_a(&w.issuer, &c).unwrap(), c),
        Design::C => (make_chain(w, &c, rng).token, c),
    }
}
fn jset(j: &mut Json, path: &[&str], v: Json) -> bool {
    let mut cur = j;
    for (i, k) in path.iter().enumerate() {
        let last = i + 1 == path.len();
        let next = match cur {
            Json::Object(o) => o.iter_mut().find(|(kk, _)| kk == k).map(|(_, v)| v),
            Json::Array(a) => k.parse::<usize>().ok().and_then(|ix| a.get_mut(ix)),
            _ => None,
        };
        let Some(next) = next else { return false };
        if last {
            *next = v;
            return true;
        }
        cur = next;
    }
    false
}
fn jget<'a>(j: &'a Json, path: &[&str]) -> Option<&'a Json> {
    let mut cur = j;
    for k in path {
        cur = match cur {
            Json::Object(o) => o.iter().find(|(kk, _)| kk == k).map(|(_, v)| v)?,
            Json::Array(a) => a.get(k.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}
fn jremove(j: &mut Json, path: &[&str]) -> bool {
    let (last, head) = path.split_last().unwrap();
    let mut cur = j;
    for k in head {
        cur = match cur {
            Json::Object(o) => match o.iter_mut().find(|(kk, _)| kk == k) {
                Some((_, v)) => v,
                None => return false,
            },
            Json::Array(a) => match k.parse::<usize>().ok().and_then(|ix| a.get_mut(ix)) {
                Some(v) => v,
                None => return false,
            },
            _ => return false,
        };
    }
    if let Json::Object(o) = cur {
        let before = o.len();
        o.retain(|(k, _)| k != last);
        return o.len() < before;
    }
    false
}
fn sig_path(d: Design, bytes: &[u8]) -> Vec<String> {
    match d {
        Design::A => vec!["sig".into()],
        Design::C => {
            let j = parse(bytes).unwrap();
            let nb = match jget(&j, &["blocks"]) {
                Some(Json::Array(a)) => a.len(),
                _ => 0,
            };
            // the root signature, or the signature of one block
            let _ = nb;
            vec!["root".into(), "sig".into()]
        }
    }
}
fn claims_prefix(d: Design) -> Vec<&'static str> {
    match d {
        Design::A => vec!["claims"],
        Design::C => vec!["root", "claims"],
    }
}

// ----------------------------------------------------------------------------------------------------------------- the attack classes
fn forged_or_edited(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for _ in 0..N {
            let (b, _) = token(d, w, rng);
            let mut j = parse(&b).unwrap();
            let pre = claims_prefix(d);
            let field = *rng.pick(&[
                "token_id",
                "subject",
                "tier",
                "corpora",
                "actions",
                "spend_cap",
                "rate_cap",
                "not_before",
                "expiry",
                "audience",
                "parent",
            ]);
            let mut path = pre.clone();
            path.push(field);
            let old = jget(&j, &path).cloned().unwrap();
            let new = match (&old, field) {
                (_, "tier") => Json::Str(if old == Json::Str("t3".into()) {
                    "t0".into()
                } else {
                    "t3".into()
                }),
                (Json::Num(n), _) => Json::Num(n.wrapping_add(1 + rng.below(1000) as u64)),
                (Json::Str(s), "audience") => Json::Str(format!("{s}x")),
                (Json::Str(_), _) => Json::Str(rng.hex(32)),
                (Json::Array(a), "corpora") => {
                    let mut v = a.clone();
                    v.push(Json::Str(corpus(9)));
                    Json::Array(v)
                }
                (Json::Array(a), _) => {
                    let mut v = a.clone();
                    v.push(Json::Str("zz_extra".into()));
                    Json::Array(v)
                }
                (Json::Null, _) => Json::Str(rng.hex(32)),
                _ => Json::Null,
            };
            assert!(jset(&mut j, &path, new));
            r.attack(
                "forged_or_edited_claims",
                d,
                run(d, &write(&j), w, &policy(), Some(&w.rev), None),
            );
        }
    }
}

fn stripped_signature(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for i in 0..N {
            let (b, _) = token(d, w, rng);
            let mut j = parse(&b).unwrap();
            let sp = sig_path(d, &b);
            let path: Vec<&str> = sp.iter().map(String::as_str).collect();
            match i % 4 {
                0 => assert!(jremove(&mut j, &path)),
                1 => assert!(jset(&mut j, &path, Json::Str(String::new()))),
                2 => assert!(jset(&mut j, &path, Json::Null)),
                _ => assert!(jset(&mut j, &path, Json::Str("0".repeat(6618)))),
            }
            r.attack(
                "stripped_signature",
                d,
                run(d, &write(&j), w, &policy(), Some(&w.rev), None),
            );
        }
    }
}

fn swapped_signature(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for i in 0..N {
            let (b, _) = token(d, w, rng);
            let (other, _) = token(d, w, rng);
            let oj = parse(&other).unwrap();
            let mut j = parse(&b).unwrap();
            let sp = sig_path(d, &b);
            let path: Vec<&str> = sp.iter().map(String::as_str).collect();
            let sig = match i % 5 {
                0 => jget(&oj, &path).cloned().unwrap(), // a valid signature of another token
                1 => Json::Str(w.untrusted.sign_hex(b"some message")), // a signature by another key
                2 => {
                    let rv = parse(&entropa_tokens::empty_revocations(&w.issuer, NOW)).unwrap(); // the issuer's signature of another kind of message
                    jget(&rv, &["sig"]).cloned().unwrap()
                }
                3 => Json::Str(rng.hex(6618)), // random bytes of the right length
                _ => {
                    let rv = parse(&issue_a(&w.issuer, &claims(rng)).unwrap()).unwrap(); // the issuer's signature of a design A token placed in the other design
                    jget(&rv, &["sig"]).cloned().unwrap()
                }
            };
            if jget(&j, &path) == Some(&sig) {
                continue;
            }
            assert!(jset(&mut j, &path, sig));
            r.attack(
                "swapped_signature",
                d,
                run(d, &write(&j), w, &policy(), Some(&w.rev), None),
            );
        }
    }
}

fn algorithm_and_key_id_confusion(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for i in 0..N {
            let (b, _) = token(d, w, rng);
            let mut j = parse(&b).unwrap();
            match i % 6 {
                0 => {
                    let alg = *rng.pick(&[
                        "none",
                        "None",
                        "ML-DSA-44",
                        "ML-DSA-87",
                        "HS256",
                        "RS256",
                        "ES256",
                        "EdDSA",
                        "ml-dsa-65",
                        "",
                        "ML-DSA-65 ",
                        "SLH-DSA-128s",
                    ]);
                    assert!(jset(&mut j, &["alg"], Json::Str(alg.into())));
                }
                1 => assert!(jset(&mut j, &["alg"], Json::Num(65))),
                2 => assert!(jremove(&mut j, &["alg"])),
                3 => {
                    // the key id of ANOTHER trusted key: the signature does not verify under it
                    let kid = entropa_tokens::key_id_of(&w.other_trusted.pubkey_hex()).unwrap();
                    assert!(jset(&mut j, &["key_id"], Json::Str(kid)));
                }
                4 => {
                    let kid = entropa_tokens::key_id_of(&w.untrusted.pubkey_hex()).unwrap();
                    assert!(jset(&mut j, &["key_id"], Json::Str(kid)));
                }
                _ => {
                    let bad = [
                        rng.hex(15),
                        rng.hex(17),
                        String::new(),
                        "ZZZZZZZZZZZZZZZZ".into(),
                        entropa_tokens::key_id_of(&w.issuer.pubkey_hex())
                            .unwrap()
                            .to_uppercase(),
                    ];
                    assert!(jset(&mut j, &["key_id"], Json::Str(rng.pick(&bad).clone())));
                }
            }
            r.attack(
                "algorithm_and_key_id_confusion",
                d,
                run(d, &write(&j), w, &policy(), Some(&w.rev), None),
            );
        }
    }
}

fn widened_child(r: &mut Report, w: &World, rng: &mut Rng) {
    for i in 0..N {
        // design A: the issuer's own re-issue helper refuses; a (buggy or malicious) issuer that signs a widened child is caught when the parent is presented
        let parent_c = claims(rng);
        let parent = issue_a(&w.issuer, &parent_c).unwrap();
        let mut c = Claims {
            token_id: rng.hex(32),
            parent: Some(parent_c.token_id.clone()),
            ..parent_c.clone()
        };
        match i % 7 {
            0 => c.corpora.push(corpus(9)),
            1 => c.actions.push("zzz_admin".into()),
            2 => c.spend_cap += 1 + rng.below(1000) as u64,
            3 => c.rate_cap += 1 + rng.below(100) as u64,
            4 => {
                c.tier = if parent_c.tier == Tier::T3 {
                    c.tier
                } else {
                    Tier::T3
                }
            }
            5 => c.expiry += 1 + rng.below(200) as u64,
            _ => c.not_before -= 1 + rng.below(50) as u64,
        }
        let mut pol = policy();
        if i % 11 == 10 {
            // a child for another node (or another subject) is a widening: it is judged at the node it names
            c = Claims {
                token_id: rng.hex(32),
                parent: Some(parent_c.token_id.clone()),
                ..parent_c.clone()
            };
            if i % 2 == 0 {
                c.audience = "node-2".into();
                pol.audience = "node-2".into();
            } else {
                c.subject = format!("{}-other", parent_c.subject);
            }
        }
        if i % 7 == 4 && i % 11 != 10 && parent_c.tier == Tier::T3 {
            c.spend_cap += 1;
        }
        assert!(
            narrow_a(&w.issuer, &parent, &c).is_err(),
            "the library made a widened child"
        );
        let forged = issue_a(&w.issuer, &c).unwrap();
        r.attack(
            "widened_child",
            Design::A,
            verify_a(&forged, &w.trust, &pol, Some(&w.rev), Some(&parent)).map(|_| ()),
        );
    }
    for i in 0..N {
        // design C: a holder with the REAL committed key signs a widening block (the signature is valid; the content is not allowed)
        let c = claims(rng);
        let mut wal = make_chain(w, &c, rng);
        if i % 3 == 0 {
            wal = append_c(
                &wal,
                &Narrowing {
                    corpora: Some(vec![corpus(0)]),
                    actions: Some(vec!["search".into()]),
                    expiry: Some(c.expiry - 50),
                    ..Narrowing::default()
                },
            )
            .unwrap();
        }
        let n = match i % 7 {
            0 => Narrowing {
                corpora: Some((0..5).map(corpus).collect()),
                ..Narrowing::default()
            },
            1 => Narrowing {
                actions: Some(vec!["admin_all".into()]),
                ..Narrowing::default()
            },
            2 => Narrowing {
                spend_cap: Some(u64::MAX),
                ..Narrowing::default()
            },
            3 => Narrowing {
                rate_cap: Some(u64::MAX),
                ..Narrowing::default()
            },
            4 => Narrowing {
                tier: Some(Tier::T3),
                spend_cap: Some(u64::MAX),
                ..Narrowing::default()
            },
            5 => Narrowing {
                expiry: Some(c.expiry + 1 + rng.below(1000) as u64),
                ..Narrowing::default()
            },
            _ => Narrowing {
                not_before: Some(c.not_before - 1 - rng.below(50) as u64),
                ..Narrowing::default()
            },
        };
        let bad = append_c_unchecked(&wal, &n);
        if bad.token == wal.token {
            continue;
        }
        r.attack(
            "widened_child",
            Design::C,
            verify_c(&bad.token, &w.trust, &policy(), Some(&w.rev)).map(|_| ()),
        );
    }
}

fn replay_after_expiry(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for _ in 0..N {
            let (b, _) = token(d, w, rng);
            let at = NOW + 700 + 1500 * 2 + rng.below(10_000_000) as u64; // after the latest possible expiry (NOW + 1599)
            let rev = entropa_tokens::empty_revocations(&w.issuer, at);
            r.attack(
                "replay_after_expiry",
                d,
                run(
                    d,
                    &b,
                    w,
                    &Policy {
                        now: at,
                        ..policy()
                    },
                    Some(&rev),
                    None,
                ),
            );
        }
    }
}

fn cross_audience(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for i in 0..N {
            let (b, _) = token(d, w, rng);
            let aud = match i % 4 {
                0 => format!("node-{}", 2 + rng.below(50)),
                1 => "node-1x".to_string(),
                2 => "Node-1".to_string(),
                _ => String::new(),
            };
            r.attack(
                "cross_audience_replay",
                d,
                run(
                    d,
                    &b,
                    w,
                    &Policy {
                        audience: aud,
                        ..policy()
                    },
                    Some(&w.rev),
                    None,
                ),
            );
        }
    }
}

fn revoked(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for i in 0..N {
            let (b, c) = token(d, w, rng);
            let mut entries: Vec<(String, u64, Reason)> = (0..rng.below(5))
                .map(|_| (rng.hex(32), NOW - 10, Reason::Superseded))
                .collect();
            entries.push((
                c.token_id.clone(),
                NOW - rng.below(1000) as u64,
                *rng.pick(&[Reason::Compromise, Reason::Requested, Reason::Superseded]),
            ));
            let signer = if i % 2 == 0 {
                &w.issuer
            } else {
                &w.other_trusted
            };
            let list = issue_revocations(signer, NOW - rng.below(300) as u64, &entries);
            r.attack("revoked", d, run(d, &b, w, &policy(), Some(&list), None));
        }
    }
    // a child of a revoked parent (design A) and a chain whose root is revoked (design C, covered by the loop above for chains of 0 to 2 blocks)
    for _ in 0..N {
        let pc = claims(rng);
        let parent = issue_a(&w.issuer, &pc).unwrap();
        let child = narrow_a(
            &w.issuer,
            &parent,
            &Claims {
                token_id: rng.hex(32),
                spend_cap: pc.spend_cap - 1,
                ..pc.clone()
            },
        )
        .unwrap();
        let list = issue_revocations(
            &w.issuer,
            NOW,
            &[(pc.token_id.clone(), NOW - 1, Reason::Compromise)],
        );
        r.attack(
            "revoked",
            Design::A,
            verify_a(&child, &w.trust, &policy(), Some(&list), None).map(|_| ()),
        );
    }
}

fn stale_missing_or_unsigned_revocation(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for i in 0..N {
            let (b, _) = token(d, w, rng);
            let list: Option<Vec<u8>> = match i % 8 {
                0 => None,
                1 => Some(entropa_tokens::empty_revocations(
                    &w.issuer,
                    NOW - 301 - rng.below(100_000) as u64,
                )),
                2 => Some(entropa_tokens::empty_revocations(
                    &w.issuer,
                    NOW + 31 + rng.below(100_000) as u64,
                )),
                3 => Some(entropa_tokens::empty_revocations(&w.untrusted, NOW)),
                4 => {
                    let mut j = parse(&entropa_tokens::empty_revocations(&w.issuer, NOW)).unwrap();
                    assert!(jremove(&mut j, &["sig"]));
                    Some(write(&j))
                }
                5 => {
                    let mut j = parse(&entropa_tokens::empty_revocations(&w.issuer, NOW)).unwrap();
                    assert!(jset(&mut j, &["issued_at"], Json::Num(NOW + 1))); // an edit to a signed list
                    Some(write(&j))
                }
                6 => Some(Vec::new()),
                _ => Some(rng.hex(40).into_bytes()),
            };
            r.attack(
                "stale_or_missing_revocation_list",
                d,
                run(d, &b, w, &policy(), list.as_deref(), None),
            );
        }
    }
}

fn clock_skew_boundaries(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for i in 0..N {
            let mut c = claims(rng);
            c.not_before = NOW - 1000 + rng.below(2000) as u64;
            c.expiry = c.not_before + 100 + rng.below(3000) as u64;
            let b = make(d, w, &c);
            // the instant a token must be refused ...
            let (now, must_deny) = match i % 6 {
                0 => (c.not_before - 31, true),
                1 => (c.expiry, true),
                2 => (c.expiry + 1, true),
                3 => (c.not_before - 30 - 1 - rng.below(5000) as u64, true),
                4 => (c.not_before - 30, false), // ... and the instants it must be ACCEPTED (controls)
                _ => (c.expiry - 1, false),
            };
            let p = Policy { now, ..policy() };
            let rev = entropa_tokens::empty_revocations(&w.issuer, now);
            let res = run(d, &b, w, &p, Some(&rev), None);
            if must_deny {
                r.attack("clock_skew_boundaries", d, res);
            } else {
                r.control("clock_skew_boundaries_accept", d, res.is_ok());
            }
            // the TTL cap and the revocation-age boundaries
            let mut t = claims(rng);
            t.not_before = NOW - 10;
            t.expiry = t.not_before + if i % 2 == 0 { 3601 } else { 3600 };
            let tb = make(d, w, &t);
            let ttl = run(d, &tb, w, &policy(), Some(&w.rev), None);
            if i % 2 == 0 {
                r.attack("clock_skew_boundaries", d, ttl);
            } else {
                r.control("clock_skew_boundaries_accept", d, ttl.is_ok());
            }
            let age = if i % 2 == 0 { 301 } else { 300 };
            let lst = entropa_tokens::empty_revocations(&w.issuer, NOW - age);
            let res = run(d, &b_for_now(d, w, rng), w, &policy(), Some(&lst), None);
            if i % 2 == 0 {
                r.attack("clock_skew_boundaries", d, res);
            } else {
                r.control("clock_skew_boundaries_accept", d, res.is_ok());
            }
        }
    }
}
fn b_for_now(d: Design, w: &World, rng: &mut Rng) -> Vec<u8> {
    token(d, w, rng).0
}

fn truncated_and_padded(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for i in 0..N {
            let (b, _) = token(d, w, rng);
            let m: Vec<u8> = match i % 10 {
                0 => b[..rng.below(b.len())].to_vec(),
                1 => b[..b.len() - 1 - rng.below(40).min(b.len() - 2)].to_vec(),
                2 => [&b[..], b" "].concat(),
                3 => [&b[..], b"\n"].concat(),
                4 => [&b"\xef\xbb\xbf"[..], &b[..]].concat(),
                5 => [&b" "[..], &b[..]].concat(),
                6 => [&b[..], &vec![0u8; 1 + rng.below(100)][..]].concat(),
                7 => [&b[..], &b[..]].concat(),
                8 => {
                    // pad the signature hex
                    let mut j = parse(&b).unwrap();
                    let sp = sig_path(d, &b);
                    let path: Vec<&str> = sp.iter().map(String::as_str).collect();
                    let s = jget(&j, &path).and_then(Json::as_str).unwrap().to_string();
                    assert!(jset(
                        &mut j,
                        &path,
                        Json::Str({
                            let k = 2 + 2 * rng.below(10);
                            format!("{s}{}", rng.hex(k))
                        })
                    ));
                    write(&j)
                }
                _ => {
                    // cut the signature hex short
                    let mut j = parse(&b).unwrap();
                    let sp = sig_path(d, &b);
                    let path: Vec<&str> = sp.iter().map(String::as_str).collect();
                    let s = jget(&j, &path).and_then(Json::as_str).unwrap().to_string();
                    assert!(jset(
                        &mut j,
                        &path,
                        Json::Str(s[..s.len() - 2 - rng.below(100)].to_string())
                    ));
                    write(&j)
                }
            };
            r.attack(
                "truncated_and_padded_encodings",
                d,
                run(d, &m, w, &policy(), Some(&w.rev), None),
            );
        }
    }
}

fn duplicate_key_and_unicode(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for i in 0..N {
            let (b, _) = token(d, w, rng);
            let text = String::from_utf8(b.clone()).unwrap();
            if i % 9 == 8 && d == Design::C && i % 2 == 0 {
                // a holder with the real key signs a block whose narrow object repeats a key: the first value narrows, the second widens
                r.attack(
                    "duplicate_key_and_unicode_tricks",
                    d,
                    run(
                        d,
                        &dup_narrow_block(w, rng),
                        w,
                        &policy(),
                        Some(&w.rev),
                        None,
                    ),
                );
                continue;
            }
            let m: Vec<u8> = match i % 9 {
                // a forged first occurrence of a key, the real value later (serde-style last-wins would accept; we refuse)
                0 => text
                    .replacen("{\"alg\":", "{\"alg\":\"none\",\"alg\":", 1)
                    .into_bytes(),
                1 => text.replacen("\"v\":1", "\"v\":2,\"v\":1", 1).into_bytes(),
                2 => text
                    .replacen(
                        "\"key_id\":\"",
                        &format!("\"key_id\":\"{}\",\"key_id\":\"", rng.hex(16)),
                        1,
                    )
                    .into_bytes(),
                3 => text
                    .replacen("\"subject\":\"", "\"subject\":\"evil\",\"subject\":\"", 1)
                    .into_bytes(),
                4 => text
                    .replacen(
                        "\"audience\":\"node-1\"",
                        "\"audience\":\"node-9\",\"audience\":\"node-1\"",
                        1,
                    )
                    .into_bytes(),
                // unicode and escape tricks inside strings
                5 => text
                    .replacen("\"subject\":\"agent", "\"subject\":\"\u{0430}gent", 1)
                    .into_bytes(), // Cyrillic a
                6 => text
                    .replacen(
                        "\"audience\":\"node-1\"",
                        "\"audience\":\"node\u{2011}1\"",
                        1,
                    )
                    .into_bytes(), // non-breaking hyphen
                7 => text
                    .replacen(
                        "\"audience\":\"node-1\"",
                        &format!("\"audience\":\"node-1{}\"", '\u{200b}'),
                        1,
                    )
                    .into_bytes(), // zero-width space
                _ if i % 2 == 0 => text
                    .replacen(
                        "\"audience\":\"node-1\"",
                        "\"audience\":\"nod\\u0065-1\"",
                        1,
                    )
                    .into_bytes(), // an escape
                _ => format!(
                    "{{\"v\":1,{}",
                    text.replacen(",\"v\":1}", "}", 1)
                        .strip_prefix('{')
                        .unwrap()
                )
                .into_bytes(), // the same members in a different order
            };
            if m == b {
                continue;
            }
            // the audience tricks are only an attack against a verifier whose audience is the tricked value; test both ways
            r.attack(
                "duplicate_key_and_unicode_tricks",
                d,
                run(d, &m, w, &policy(), Some(&w.rev), None),
            );
        }
    }
}

/// A design C token whose last block was appended by the real holder but whose narrow object repeats `spend_cap` (a lower value first, a
/// higher one second). Built with the public pieces: the digest, the canonical writer and the holder's key.
fn dup_narrow_block(w: &World, rng: &mut Rng) -> Vec<u8> {
    let c = claims(rng);
    let wal = issue_c(&w.issuer, &c).unwrap();
    let mut j = parse(&wal.token).unwrap();
    let root_sig = jget(&j, &["root", "sig"])
        .and_then(Json::as_str)
        .unwrap()
        .to_string();
    let eph = Probe::spawn();
    let narrow = Json::Object(vec![
        ("spend_cap".into(), Json::Num(1)),
        ("spend_cap".into(), Json::Num(c.spend_cap)),
    ]);
    let prev = hex_blake3(root_sig.as_bytes());
    let msg = Json::Object(vec![
        ("narrow".into(), narrow.clone()),
        ("next_pubkey".into(), Json::Str(eph.pubkey_hex())),
        ("prev".into(), Json::Str(prev.clone())),
    ]);
    let sig = wal
        .key
        .sign_hex(&entropa_tokens::digest("c-block", &write(&msg)));
    let block = Json::Object(vec![
        ("narrow".into(), narrow),
        ("next_pubkey".into(), Json::Str(eph.pubkey_hex())),
        ("prev".into(), Json::Str(prev)),
        ("sig".into(), Json::Str(sig)),
    ]);
    assert!(jset(&mut j, &["blocks"], Json::Array(vec![block])));
    write(&j)
}
fn hex_blake3(b: &[u8]) -> String {
    blake3::hash(b)
        .as_bytes()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

// ----------------------------------------------------------------------------------------------------------- cross-context classes
fn jstr(x: &str) -> Json {
    Json::Str(x.into())
}
fn drop_member(members: &[(&str, Json)], drop: Option<&str>) -> Json {
    Json::Object(
        members
            .iter()
            .filter(|(k, _)| Some(*k) != drop)
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect(),
    )
}
const TAGS: [&str; 6] = [
    "c-root",
    "c-block",
    "revocations",
    "",
    "a-token ",
    "entropa-token-v1",
];

/// Signatures made by the REAL issuer or holder, correctly formed, but over a different message than the verifier rebuilds.
fn signature_over_a_different_message(r: &mut Report, w: &World, rng: &mut Rng) {
    for i in 0..N {
        let c = claims(rng);
        let kid = entropa_tokens::key_id_of(&w.issuer.pubkey_hex()).unwrap();
        // design A: wrong tag, or a member left out of the signed message
        let full = [
            ("alg", jstr(entropa_tokens::ALG)),
            ("claims", c.to_json()),
            ("key_id", jstr(&kid)),
            ("v", Json::Num(1)),
        ];
        let (tag, drop) = if i % 2 == 0 {
            (*rng.pick(&TAGS), None)
        } else {
            (
                "a-token",
                Some(*rng.pick(&["alg", "claims", "key_id", "v"])),
            )
        };
        let sig = w.issuer.sign_hex(&entropa_tokens::digest(
            tag,
            &write(&drop_member(&full, drop)),
        ));
        let mut o: Vec<(String, Json)> = full
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect();
        o.push(("sig".into(), Json::Str(sig)));
        r.attack(
            "signature_over_a_different_message",
            Design::A,
            run(
                Design::A,
                &write(&Json::Object(o)),
                w,
                &policy(),
                Some(&w.rev),
                None,
            ),
        );
        // design C root
        let eph = Probe::spawn().pubkey_hex();
        let msg = [
            ("alg", jstr(entropa_tokens::ALG)),
            ("claims", c.to_json()),
            ("key_id", jstr(&kid)),
            ("next_pubkey", jstr(&eph)),
            ("v", Json::Num(1)),
        ];
        let (tag, drop) = if i % 2 == 0 {
            (
                *rng.pick(&["a-token", "c-block", "revocations", "", "C-ROOT"]),
                None,
            )
        } else {
            (
                "c-root",
                Some(*rng.pick(&["alg", "claims", "key_id", "next_pubkey", "v"])),
            )
        };
        let sig = w.issuer.sign_hex(&entropa_tokens::digest(
            tag,
            &write(&drop_member(&msg, drop)),
        ));
        let tok = write(&Json::Object(vec![
            ("alg".into(), jstr(entropa_tokens::ALG)),
            ("blocks".into(), Json::Array(vec![])),
            ("key_id".into(), jstr(&kid)),
            (
                "root".into(),
                Json::Object(vec![
                    ("claims".into(), c.to_json()),
                    ("next_pubkey".into(), jstr(&eph)),
                    ("sig".into(), Json::Str(sig)),
                ]),
            ),
            ("v".into(), Json::Num(1)),
        ]));
        r.attack(
            "signature_over_a_different_message",
            Design::C,
            run(Design::C, &tok, w, &policy(), Some(&w.rev), None),
        );
    }
}

/// A delegate's later block moved onto a different ancestor block that commits the SAME next key (built by the delegator, who holds the root
/// key); and the same with a block of another chain.
fn spliced_chain_blocks(r: &mut Report, w: &World, rng: &mut Rng) {
    let mut made = 0;
    while made < N {
        let c = claims(rng);
        let root = issue_c(&w.issuer, &c).unwrap();
        let narrowed = append_c(
            &root,
            &Narrowing {
                corpora: Some(vec![c.corpora[0].clone()]),
                ..Narrowing::default()
            },
        )
        .unwrap();
        let delegate = append_c(
            &narrowed,
            &Narrowing {
                spend_cap: Some(c.spend_cap - 1 - rng.below(1000) as u64),
                ..Narrowing::default()
            },
        )
        .unwrap();
        let k1 = match parse(&narrowed.token).unwrap().get("blocks") {
            Some(Json::Array(b)) => b[0]
                .get("next_pubkey")
                .and_then(Json::as_str)
                .unwrap()
                .to_string(),
            _ => panic!(),
        };
        let wider = Narrowing {
            corpora: Some(c.corpora[..1 + rng.below(3)].to_vec()),
            ..Narrowing::default()
        };
        let alt = entropa_tokens::testing::append_c_committing(&root, &wider, &k1);
        let (Json::Object(mut top), Json::Object(del)) =
            (parse(&alt.token).unwrap(), parse(&delegate.token).unwrap())
        else {
            panic!()
        };
        let blocks = match del
            .iter()
            .find(|(k, _)| k == "blocks")
            .map(|(_, v)| v.clone())
        {
            Some(Json::Array(b)) => b,
            _ => panic!(),
        };
        for (k, v) in &mut top {
            if k == "blocks" {
                let Json::Array(b) = v else { panic!() };
                b.push(blocks[1].clone());
            }
        }
        let spliced = write(&Json::Object(top));
        if spliced == delegate.token {
            continue; // the "wider" ancestor happened to equal the original: not an attack
        }
        r.attack(
            "spliced_chain_blocks",
            Design::C,
            verify_c(&spliced, &w.trust, &policy(), Some(&w.rev)).map(|_| ()),
        );
        made += 1;
    }
}

/// One kind of document presented as another.
fn document_kind_confusion(r: &mut Report, w: &World, rng: &mut Rng) {
    for i in 0..N {
        let a = issue_a(&w.issuer, &claims(rng)).unwrap();
        let c = issue_c(&w.issuer, &claims(rng)).unwrap().token;
        let list = issue_revocations(&w.issuer, NOW, &[(rng.hex(32), NOW - 1, Reason::Requested)]);
        for d in [Design::A, Design::C] {
            let presented = match (i % 3, d) {
                (0, _) => list.clone(),
                (1, Design::A) => c.clone(),
                (1, Design::C) => a.clone(),
                (_, _) => rng.hex(64).into_bytes(),
            };
            r.attack(
                "document_kind_confusion",
                d,
                run(d, &presented, w, &policy(), Some(&w.rev), None),
            );
        }
        // a token where a revocation list is expected
        r.attack(
            "document_kind_confusion",
            Design::A,
            verify_a(&a, &w.trust, &policy(), Some(&c), None).map(|_| ()),
        );
        r.attack(
            "document_kind_confusion",
            Design::C,
            verify_c(&c, &w.trust, &policy(), Some(&a)).map(|_| ()),
        );
    }
}

fn controls(r: &mut Report, w: &World, rng: &mut Rng) {
    for d in [Design::A, Design::C] {
        for _ in 0..600 {
            let (b, c) = token(d, w, rng);
            let v = match d {
                Design::A => verify_a(&b, &w.trust, &policy(), Some(&w.rev), None),
                Design::C => verify_c(&b, &w.trust, &policy(), Some(&w.rev)),
            };
            r.control(
                "valid_tokens",
                d,
                v.as_ref().is_ok_and(|v| v.token_id == c.token_id),
            );
        }
    }
    // a valid chain made by two honest hops, and a valid child of a design A parent
    for _ in 0..200 {
        let c = claims(rng);
        let w1 = make_chain(w, &c, rng);
        let w2 = append_c(
            &w1,
            &Narrowing {
                actions: Some(vec!["search".into()]),
                ..Narrowing::default()
            },
        )
        .unwrap();
        r.control(
            "valid_chains",
            Design::C,
            verify_c(&w2.token, &w.trust, &policy(), Some(&w.rev)).is_ok(),
        );
        let parent = issue_a(&w.issuer, &c).unwrap();
        let child = narrow_a(
            &w.issuer,
            &parent,
            &Claims {
                token_id: rng.hex(32),
                actions: vec!["search".into()],
                ..c.clone()
            },
        )
        .unwrap();
        r.control(
            "valid_chains",
            Design::A,
            verify_a(&child, &w.trust, &policy(), Some(&w.rev), Some(&parent)).is_ok(),
        );
    }
    // a block signed by a key the token did not commit to, built here (the verifier must refuse it; counted in the swapped class too)
    let c = claims(rng);
    let wal = make_chain(w, &c, rng);
    let evil = append_c_with_key(
        &wal,
        &Narrowing {
            spend_cap: Some(1),
            ..Narrowing::default()
        },
        &w.untrusted,
    );
    r.attack(
        "swapped_signature",
        Design::C,
        verify_c(&evil.token, &w.trust, &policy(), Some(&w.rev)).map(|_| ()),
    );
}

#[test]
fn the_planted_attack_battery() {
    let w = world();
    let mut rng = Rng(0x41_54_31_20_26_11_14); // "AT1" and the date
    let mut r = Report::default();
    forged_or_edited(&mut r, &w, &mut rng);
    stripped_signature(&mut r, &w, &mut rng);
    swapped_signature(&mut r, &w, &mut rng);
    algorithm_and_key_id_confusion(&mut r, &w, &mut rng);
    widened_child(&mut r, &w, &mut rng);
    replay_after_expiry(&mut r, &w, &mut rng);
    cross_audience(&mut r, &w, &mut rng);
    revoked(&mut r, &w, &mut rng);
    stale_missing_or_unsigned_revocation(&mut r, &w, &mut rng);
    clock_skew_boundaries(&mut r, &w, &mut rng);
    truncated_and_padded(&mut r, &w, &mut rng);
    duplicate_key_and_unicode(&mut r, &w, &mut rng);
    signature_over_a_different_message(&mut r, &w, &mut rng);
    spliced_chain_blocks(&mut r, &w, &mut rng);
    document_kind_confusion(&mut r, &w, &mut rng);
    controls(&mut r, &w, &mut rng);

    let mut json = String::from("{\n \"attacks\": [\n");
    let mut failures = Vec::new();
    let mut first = true;
    for ((class, d), t) in &r.rows {
        let ub = if t.accepted == 0 {
            3.0 / t.n as f64
        } else {
            f64::NAN
        };
        println!(
            "{class:38} {d:?}  n={:4}  accepted={}  95% upper bound={:.4}  reasons={:?}",
            t.n, t.accepted, ub, t.reasons
        );
        if !first {
            json.push_str(",\n");
        }
        first = false;
        json.push_str(&format!("  {{\"class\":\"{class}\",\"design\":\"{d:?}\",\"n\":{},\"accepted\":{},\"upper95\":{},\"reasons\":{:?}}}", t.n, t.accepted, if ub.is_nan() { "null".to_string() } else { format!("{ub:.4}") }, t.reasons));
        if t.accepted > 0 || t.n < 200 {
            failures.push(format!("{class} {d:?}: accepted {} of {}", t.accepted, t.n));
        }
    }
    json.push_str("\n ],\n \"controls\": [\n");
    let mut first = true;
    for ((class, d), (n, ok)) in &r.controls {
        println!("CONTROL {class:36} {d:?}  accepted {ok} of {n}");
        if !first {
            json.push_str(",\n");
        }
        first = false;
        json.push_str(&format!(
            "  {{\"class\":\"{class}\",\"design\":\"{d:?}\",\"n\":{n},\"accepted\":{ok}}}"
        ));
        if ok != n {
            failures.push(format!("control {class} {d:?}: accepted {ok} of {n}"));
        }
    }
    json.push_str("\n ]\n}\n");
    if let Ok(path) = std::env::var("AT1_EVIDENCE") {
        std::fs::write(path, &json).unwrap();
    }
    let valid: usize = r
        .controls
        .iter()
        .filter(|((c, _), _)| c == "valid_tokens" || c == "valid_chains")
        .map(|(_, (n, _))| *n)
        .sum();
    assert!(valid >= 1000, "controls: {valid}");
    assert!(failures.is_empty(), "{failures:#?}");
}
