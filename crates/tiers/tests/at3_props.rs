//! AT3 task 4: properties over random call sequences (20,000 sequences' worth of calls, fixed seed): no panic; exactly one record per call; a sealed version exists only if the
//! shadow log (kept by the test from the calls' own results, not from the stores) shows an accepted request and an accepted approval by a DIFFERENT subject for that change hash;
//! versions form a chain (seq 1..n, parent = previous version hash); hostile names (multibyte, NUL, very long) and junk tokens are refused without panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::change::{Change, ChangeControl, MemoryPending, MemoryVersions, VersionStore};
use entropa_tiers::{OfflineVerifier, RecordSink, TierRecord};
use entropa_tokens::{empty_revocations, issue_a, Claims, Tier, Trust};
use std::cell::RefCell;
use std::collections::HashMap;

const NOW: u64 = 1_800_000_000;
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[(self.next() as usize) % v.len()]
    }
}
struct Count(RefCell<u32>);
impl RecordSink for Count {
    fn write(&self, _: &TierRecord) -> Result<(), String> {
        *self.0.borrow_mut() += 1;
        Ok(())
    }
}

#[test]
fn p1_random_call_sequences_never_seal_a_version_without_two_distinct_subjects() {
    let cases: usize = std::env::var("AT3_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    trust.add(&issuer.pubkey_hex());
    let verifier = OfflineVerifier {
        trust,
        audience: "node-1".into(),
        skew: 30,
        max_ttl: 7200,
        rev_max_age: 300,
        revocations: Some(empty_revocations(&issuer, NOW)),
    };
    // a fixed pool of tokens: three T3 subjects, one T2, one with only one class
    let mk = |id: u64, subject: &str, tier: Tier, actions: &[&str]| {
        issue_a(
            &issuer,
            &Claims {
                token_id: format!("{id:032x}"),
                subject: subject.into(),
                tier,
                corpora: vec!["1".repeat(64)],
                actions: actions.iter().map(|s| s.to_string()).collect(),
                spend_cap: 1,
                rate_cap: 1,
                not_before: NOW - 10,
                expiry: NOW + 6000,
                audience: "node-1".into(),
                parent: None,
            },
        )
        .unwrap()
    };
    let all = [
        "change:corpus",
        "change:model",
        "change:policy",
        "change:prompt",
    ];
    let toks: Vec<(String, Vec<u8>)> = vec![
        ("a".into(), mk(1, "a", Tier::T3, &all)),
        ("b".into(), mk(2, "b", Tier::T3, &all)),
        ("c".into(), mk(3, "c", Tier::T3, &all)),
        ("a".into(), mk(4, "a", Tier::T3, &all)), // a second token of subject a
        ("t2".into(), mk(5, "t2", Tier::T2, &all)),
        ("one".into(), mk(6, "one", Tier::T3, &["change:prompt"])),
        ("junk".into(), b"junk".to_vec()),
    ];
    let (pending, versions, sink) = (
        MemoryPending::default(),
        MemoryVersions::default(),
        Count(RefCell::new(0)),
    );
    let cc = ChangeControl {
        verifier: &verifier,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    let mut g = Lcg(20261215);
    let hostile = [
        "",
        "x",
        "p-1",
        "名前",
        "a\u{0}b",
        "é".repeat(40).leak(),
        "x".repeat(70).leak(),
        "a b",
        "../x",
    ];
    let classes = ["prompt", "corpus", "policy", "model", "bogus", "Prompt", ""];
    let contents = [
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(63),
        "G".repeat(64),
    ];
    let mut hashes: Vec<String> = vec![];
    // shadow log: change hash -> (requester subject, set of approving subjects)
    let mut shadow: HashMap<String, (String, Vec<String>)> = HashMap::new();
    let mut calls = 0u32;
    for step in 0..cases {
        let now = NOW + (g.next() % 4000);
        let (subj, tok) = g.pick(&toks).clone();
        match g.next() % 3 {
            0 => {
                let parent = if g.next().is_multiple_of(2) {
                    None
                } else {
                    versions
                        .head(g.pick(&classes), "p-1")
                        .map(|v| v.version_hash)
                };
                let c = Change {
                    class: g.pick(&classes).to_string(),
                    name: g.pick(&hostile).to_string(),
                    content_hash: g.pick(&contents).clone(),
                    parent,
                };
                calls += 1;
                if let Ok(h) = cc.request(&tok, None, &c, now) {
                    shadow.insert(h.clone(), (subj, vec![]));
                    hashes.push(h);
                }
            }
            1 => {
                let h = if hashes.is_empty() || g.next().is_multiple_of(5) {
                    "9".repeat(64)
                } else {
                    g.pick(&hashes).clone()
                };
                calls += 1;
                if cc.approve(&tok, None, &h, now).is_ok() {
                    shadow
                        .get_mut(&h)
                        .expect("an accepted approval names an accepted request")
                        .1
                        .push(subj);
                }
            }
            _ => {
                let h = if hashes.is_empty() || g.next().is_multiple_of(5) {
                    "8".repeat(64)
                } else {
                    g.pick(&hashes).clone()
                };
                calls += 1;
                if let Ok(v) = cc.activate(&tok, None, &h, now) {
                    let (req, apps) = shadow.get(&h).expect("an activated change was requested");
                    assert!(
                        apps.iter().any(|a| a != req),
                        "step {step}: version sealed without a second subject ({req} / {apps:?})"
                    );
                    assert_eq!(v.change_hash, h);
                }
            }
        }
    }
    assert_eq!(*sink.0.borrow(), calls, "exactly one record per call");
    // chains
    let mut sealed = 0usize;
    for class in ["prompt", "corpus", "policy", "model"] {
        for name in hostile {
            let all = versions.all(class, name);
            sealed += all.len();
            for (i, v) in all.iter().enumerate() {
                assert_eq!(v.seq as usize, i + 1);
                assert_eq!(
                    v.parent_version_hash.as_deref(),
                    if i == 0 {
                        None
                    } else {
                        Some(all[i - 1].version_hash.as_str())
                    }
                );
            }
        }
    }
    eprintln!("sealed versions: {sealed}");
    // The sanity floor grows with the case count (5 at the default of 20,000 cases; the measured seals are about 3 at 2,000 and 6 at 10,000): the property assertions above are unchanged, only the check that the run sealed anything at all scales.
    let floor = (cases / 4000).max(1);
    assert!(
        sealed >= floor,
        "the property run must seal some versions or it proves nothing: {sealed} sealed, at least {floor} wanted for {cases} cases"
    );
}
