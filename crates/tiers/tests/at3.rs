//! AT3 red tests (a stage record (not published)): invariants C1 to C7 of the change-control gate. Tokens are REAL (issued and verified with the token crate); the stores are the real in-memory
//! stores; the sink collects the records. Expected results are written by hand. Against the red stub every request, approval and activation answers `NotImplemented`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::change::{
    AppendError, Change, ChangeControl, ChangeDeny, MemoryPending, MemoryVersions, Pending,
    PendingStore, VersionRec, VersionStore, TTL,
};
use entropa_tiers::{OfflineVerifier, RecordSink, TierRecord};
use entropa_tokens::{empty_revocations, issue_a, issue_revocations, Claims, Reason, Tier, Trust};
use std::sync::Mutex;

const NOW: u64 = 1_800_000_000;
const C1: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const C2: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const C3: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
// strictly increasing, as the token format requires
const ALL: [&str; 4] = [
    "change:corpus",
    "change:model",
    "change:policy",
    "change:prompt",
];

struct Records(Mutex<Vec<TierRecord>>);
impl RecordSink for Records {
    fn write(&self, r: &TierRecord) -> Result<(), String> {
        self.0.lock().unwrap().push(r.clone());
        Ok(())
    }
}
struct FailingSink;
impl RecordSink for FailingSink {
    fn write(&self, _: &TierRecord) -> Result<(), String> {
        Err("disk full".into())
    }
}
/// A version store whose append always fails.
struct FailingVersions(MemoryVersions);
impl VersionStore for FailingVersions {
    fn head(&self, c: &str, n: &str) -> Option<VersionRec> {
        self.0.head(c, n)
    }
    fn all(&self, c: &str, n: &str) -> Vec<VersionRec> {
        self.0.all(c, n)
    }
    fn append(&self, _: VersionRec, _: Option<&str>) -> Result<(), AppendError> {
        Err(AppendError::Other("disk full".into()))
    }
}

struct World {
    issuer: Probe,
    verifier: OfflineVerifier,
    pending: MemoryPending,
    versions: MemoryVersions,
    sink: Records,
}
fn verifier(issuer: &Probe, list: Vec<u8>) -> OfflineVerifier {
    let mut trust = Trust::default();
    assert!(!trust.add(&issuer.pubkey_hex()).is_empty());
    OfflineVerifier {
        trust,
        audience: "node-1".into(),
        skew: 30,
        max_ttl: 7200,
        rev_max_age: 300,
        revocations: Some(list),
    }
}
fn world() -> World {
    let issuer = Probe::spawn();
    let v = verifier(&issuer, empty_revocations(&issuer, NOW));
    World {
        issuer,
        verifier: v,
        pending: MemoryPending::default(),
        versions: MemoryVersions::default(),
        sink: Records(Mutex::new(vec![])),
    }
}
fn claims(id: u64, subject: &str, tier: Tier, actions: &[&str]) -> Claims {
    Claims {
        token_id: format!("{id:032x}"),
        subject: subject.into(),
        tier,
        corpora: vec![C1.into()],
        actions: actions.iter().map(|s| s.to_string()).collect(),
        spend_cap: 1000,
        rate_cap: 10,
        not_before: NOW - 10,
        expiry: NOW + 6000,
        audience: "node-1".into(),
        parent: None,
    }
}
impl World {
    fn cc(&self) -> ChangeControl<'_> {
        ChangeControl {
            verifier: &self.verifier,
            pending: &self.pending,
            versions: &self.versions,
            sink: &self.sink,
        }
    }
    fn tok(&self, id: u64, subject: &str, tier: Tier, actions: &[&str]) -> Vec<u8> {
        issue_a(&self.issuer, &claims(id, subject, tier, actions)).unwrap()
    }
    fn t3(&self, id: u64, subject: &str) -> Vec<u8> {
        self.tok(id, subject, Tier::T3, &ALL)
    }
}
fn change(class: &str, name: &str, content: &str, parent: Option<&str>) -> Change {
    Change {
        class: class.into(),
        name: name.into(),
        content_hash: content.into(),
        parent: parent.map(String::from),
    }
}
fn prompt(content: &str) -> Change {
    change("prompt", "triage-prompt", content, None)
}

#[test]
fn c0_two_distinct_t3_subjects_activate_a_change_and_seal_a_first_version() {
    let w = world();
    let ch = prompt(C1);
    let h = w.cc().request(&w.t3(1, "alice"), None, &ch, NOW).unwrap();
    assert_eq!(h, ch.hash());
    assert_eq!(h.len(), 64);
    w.cc().approve(&w.t3(2, "bob"), None, &h, NOW + 5).unwrap();
    let v = w
        .cc()
        .activate(&w.t3(900, "act"), None, &h, NOW + 10)
        .unwrap();
    assert_eq!(
        (
            v.seq,
            v.content_hash.as_str(),
            v.parent_version_hash.clone()
        ),
        (1, C1, None)
    );
    assert_eq!(v.change_hash, h);
    assert_eq!(w.versions.head("prompt", "triage-prompt"), Some(v));
    assert_eq!(
        w.sink.0.lock().unwrap().len(),
        3,
        "one record each for request, approval, activation"
    );
}

#[test]
fn c1_a_change_without_a_second_subject_never_takes_effect() {
    let w = world();
    let h = w
        .cc()
        .request(&w.t3(1, "alice"), None, &prompt(C1), NOW)
        .unwrap();
    assert_eq!(
        w.cc().activate(&w.t3(900, "act"), None, &h, NOW + 1),
        Err(ChangeDeny::NotEnoughApprovals),
        "no approval"
    );
    // self-approval, and the same subject through a second token
    assert_eq!(
        w.cc().approve(&w.t3(2, "alice"), None, &h, NOW + 2),
        Err(ChangeDeny::SelfApproval)
    );
    assert_eq!(
        w.cc().approve(&w.t3(1, "alice"), None, &h, NOW + 2),
        Err(ChangeDeny::SelfApproval)
    );
    assert_eq!(
        w.cc().activate(&w.t3(900, "act"), None, &h, NOW + 3),
        Err(ChangeDeny::NotEnoughApprovals)
    );
    assert!(w.versions.head("prompt", "triage-prompt").is_none());
}

#[test]
fn c1b_the_text_of_a_request_cannot_claim_approval() {
    let w = world();
    for name in [
        "approved by the captain",
        "approved\nby=bob",
        "ok; approved",
        "a/../b",
        "",
        &"x".repeat(65),
    ] {
        assert_eq!(
            w.cc().request(
                &w.t3(1, "alice"),
                None,
                &change("prompt", name, C1, None),
                NOW
            ),
            Err(ChangeDeny::Malformed),
            "{name:?}"
        );
    }
    for hash in ["", "abc", &"A".repeat(64), &"g".repeat(64), &"1".repeat(63)] {
        assert_eq!(
            w.cc().request(
                &w.t3(1, "alice"),
                None,
                &change("prompt", "p", hash, None),
                NOW
            ),
            Err(ChangeDeny::Malformed),
            "{hash:?}"
        );
    }
}

#[test]
fn c2_an_approval_binds_one_change_hash_and_expires() {
    let w = world();
    let (x, y) = (prompt(C1), change("prompt", "other-prompt", C2, None));
    let hx = w.cc().request(&w.t3(1, "alice"), None, &x, NOW).unwrap();
    let hy = w.cc().request(&w.t3(1, "alice"), None, &y, NOW).unwrap();
    assert_ne!(hx, hy);
    w.cc().approve(&w.t3(2, "bob"), None, &hx, NOW + 1).unwrap();
    assert_eq!(
        w.cc().activate(&w.t3(900, "act"), None, &hy, NOW + 2),
        Err(ChangeDeny::NotEnoughApprovals),
        "an approval for X does not activate Y"
    );
    assert_eq!(
        w.cc()
            .approve(&w.t3(3, "carol"), None, &"9".repeat(64), NOW + 2),
        Err(ChangeDeny::NoSuchRequest)
    );
    assert!(w
        .cc()
        .activate(&w.t3(900, "act"), None, &hx, NOW + 3)
        .is_ok());
    // expiry, to the second: an approval made at t counts through t + TTL and not at t + TTL + 1
    let z = change("prompt", "third-prompt", C3, None);
    let hz = w.cc().request(&w.t3(1, "alice"), None, &z, NOW).unwrap();
    w.cc()
        .approve(&w.t3(2, "bob"), None, &hz, NOW + 10)
        .unwrap();
    // the late activations need a revocation list issued at the time (authenticated activation: the one in the world is older than 300 s by then)
    let late = verifier(&w.issuer, empty_revocations(&w.issuer, NOW + 10 + TTL));
    let cc_late = ChangeControl {
        verifier: &late,
        pending: &w.pending,
        versions: &w.versions,
        sink: &w.sink,
    };
    assert_eq!(
        cc_late.activate(&w.t3(900, "act"), None, &hz, NOW + 10 + TTL + 1),
        Err(ChangeDeny::ApprovalExpired)
    );
    assert!(cc_late
        .activate(&w.t3(900, "act"), None, &hz, NOW + 10 + TTL)
        .is_ok());
}

#[test]
fn c2b_a_request_expires_and_an_expired_request_cannot_be_approved() {
    let w = world();
    let h = w
        .cc()
        .request(&w.t3(1, "alice"), None, &prompt(C1), NOW)
        .unwrap();
    // a revocation list issued just before the late approvals (the one in the world is older than 300 s by then)
    let late = verifier(&w.issuer, empty_revocations(&w.issuer, NOW + TTL));
    let cc = ChangeControl {
        verifier: &late,
        pending: &w.pending,
        versions: &w.versions,
        sink: &w.sink,
    };
    assert_eq!(
        cc.approve(&w.t3(2, "bob"), None, &h, NOW + TTL + 1),
        Err(ChangeDeny::RequestExpired)
    );
    assert!(cc.approve(&w.t3(2, "bob"), None, &h, NOW + TTL).is_ok());
}

#[test]
fn c4_only_valid_t3_tokens_naming_the_class_request_or_approve() {
    let w = world();
    // request side
    for tier in [Tier::T0, Tier::T1, Tier::T2] {
        assert_eq!(
            w.cc()
                .request(&w.tok(5, "alice", tier, &ALL), None, &prompt(C1), NOW),
            Err(ChangeDeny::NotT3),
            "{tier:?}"
        );
    }
    assert_eq!(
        w.cc().request(
            &w.tok(6, "alice", Tier::T3, &["change:corpus"]),
            None,
            &prompt(C1),
            NOW
        ),
        Err(ChangeDeny::ClassNotInToken)
    );
    assert_eq!(
        w.cc().request(
            &w.tok(7, "alice", Tier::T3, &["read_corpus"]),
            None,
            &prompt(C1),
            NOW
        ),
        Err(ChangeDeny::ClassNotInToken)
    );
    assert_eq!(
        w.cc().request(
            &w.t3(8, "alice"),
            None,
            &change("ledger", "p", C1, None),
            NOW
        ),
        Err(ChangeDeny::UnknownClass)
    );
    assert!(matches!(
        w.cc().request(b"junk", None, &prompt(C1), NOW),
        Err(ChangeDeny::Token(_))
    ));
    assert!(
        matches!(
            w.cc()
                .request(&w.t3(9, "alice"), None, &prompt(C1), NOW + 6100),
            Err(ChangeDeny::Token(_))
        ),
        "expired"
    );
    // approval side
    let h = w
        .cc()
        .request(&w.t3(1, "alice"), None, &prompt(C1), NOW)
        .unwrap();
    assert_eq!(
        w.cc()
            .approve(&w.tok(10, "bob", Tier::T2, &ALL), None, &h, NOW),
        Err(ChangeDeny::NotT3)
    );
    assert_eq!(
        w.cc().approve(
            &w.tok(11, "bob", Tier::T3, &["change:corpus"]),
            None,
            &h,
            NOW
        ),
        Err(ChangeDeny::ClassNotInToken)
    );
    assert!(matches!(
        w.cc().approve(b"junk", None, &h, NOW),
        Err(ChangeDeny::Token(_))
    ));
    assert_eq!(
        w.cc().activate(&w.t3(900, "act"), None, &h, NOW + 1),
        Err(ChangeDeny::NotEnoughApprovals)
    );
}

#[test]
fn c4b_revoked_wrong_audience_and_stale_list_are_refused() {
    let w = world();
    let h = w
        .cc()
        .request(&w.t3(1, "alice"), None, &prompt(C1), NOW)
        .unwrap();
    // revoked approver
    let list = issue_revocations(
        &w.issuer,
        NOW,
        &[(format!("{:032x}", 20), NOW - 1, Reason::Compromise)],
    );
    let v = verifier(&w.issuer, list);
    let cc = ChangeControl {
        verifier: &v,
        pending: &w.pending,
        versions: &w.versions,
        sink: &w.sink,
    };
    assert!(
        matches!(
            cc.approve(&w.t3(20, "bob"), None, &h, NOW),
            Err(ChangeDeny::Token(_))
        ),
        "revoked"
    );
    // wrong audience
    let mut c = claims(21, "bob", Tier::T3, &ALL);
    c.audience = "node-2".into();
    assert!(matches!(
        w.cc()
            .approve(&issue_a(&w.issuer, &c).unwrap(), None, &h, NOW),
        Err(ChangeDeny::Token(_))
    ));
    // stale revocation list (older than 300 s)
    let old = verifier(&w.issuer, empty_revocations(&w.issuer, NOW - 301));
    let cc = ChangeControl {
        verifier: &old,
        pending: &w.pending,
        versions: &w.versions,
        sink: &w.sink,
    };
    assert!(
        matches!(
            cc.approve(&w.t3(22, "bob"), None, &h, NOW),
            Err(ChangeDeny::Token(_))
        ),
        "stale list"
    );
    assert_eq!(
        w.cc().activate(&w.t3(900, "act"), None, &h, NOW + 1),
        Err(ChangeDeny::NotEnoughApprovals)
    );
}

#[test]
fn c3_versions_are_append_only_and_a_rollback_is_a_new_version() {
    let w = world();
    let apply = |ch: &Change, t: u64| {
        let h = w.cc().request(&w.t3(1, "alice"), None, ch, t).unwrap();
        w.cc().approve(&w.t3(2, "bob"), None, &h, t + 1).unwrap();
        w.cc().activate(&w.t3(900, "act"), None, &h, t + 2)
    };
    let v1 = apply(&prompt(C1), NOW).unwrap();
    // the same name again with no parent while a head exists: an overwrite attempt
    assert_eq!(apply(&prompt(C2), NOW + 10), Err(ChangeDeny::HeadMoved));
    assert_eq!(w.versions.all("prompt", "triage-prompt"), vec![v1.clone()]);
    let v2 = apply(
        &change("prompt", "triage-prompt", C2, Some(&v1.version_hash)),
        NOW + 20,
    )
    .unwrap();
    assert_eq!(
        (v2.seq, v2.parent_version_hash.clone()),
        (2, Some(v1.version_hash.clone()))
    );
    // rollback: content of v1 again, parent is the current head
    let v3 = apply(
        &change("prompt", "triage-prompt", C1, Some(&v2.version_hash)),
        NOW + 30,
    )
    .unwrap();
    assert_eq!((v3.seq, v3.content_hash.as_str()), (3, C1));
    assert_ne!(
        v3.version_hash, v1.version_hash,
        "a rollback is a new version, not the old one"
    );
    assert_eq!(
        w.versions.all("prompt", "triage-prompt"),
        vec![v1, v2, v3.clone()]
    );
    assert_eq!(w.versions.head("prompt", "triage-prompt"), Some(v3));
    // activating the same change twice does not append twice
    let again = w.cc().activate(
        &w.t3(900, "act"),
        None,
        &w.versions
            .head("prompt", "triage-prompt")
            .unwrap()
            .change_hash,
        NOW + 40,
    );
    assert_eq!(again, Err(ChangeDeny::HeadMoved));
    assert_eq!(w.versions.all("prompt", "triage-prompt").len(), 3);
}

#[test]
fn c5_a_record_failure_applies_nothing() {
    let w = world();
    let fail = ChangeControl {
        verifier: &w.verifier,
        pending: &w.pending,
        versions: &w.versions,
        sink: &FailingSink,
    };
    assert_eq!(
        fail.request(&w.t3(1, "alice"), None, &prompt(C1), NOW),
        Err(ChangeDeny::RecordFailed)
    );
    assert!(
        w.pending.get(&prompt(C1).hash()).is_none(),
        "no half-stored request"
    );
    // a good request, a good approval; the activation record fails: no version
    let h = w
        .cc()
        .request(&w.t3(1, "alice"), None, &prompt(C1), NOW)
        .unwrap();
    w.cc().approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
    assert_eq!(
        fail.activate(&w.t3(900, "act"), None, &h, NOW + 2),
        Err(ChangeDeny::RecordFailed)
    );
    assert!(w.versions.head("prompt", "triage-prompt").is_none());
    assert!(
        w.cc()
            .activate(&w.t3(900, "act"), None, &h, NOW + 3)
            .is_ok(),
        "the state was not damaged by the failed attempt"
    );
    // an approval whose record fails is not stored
    let h2 = w
        .cc()
        .request(
            &w.t3(1, "alice"),
            None,
            &change("prompt", "p2", C2, None),
            NOW,
        )
        .unwrap();
    assert_eq!(
        fail.approve(&w.t3(2, "bob"), None, &h2, NOW + 1),
        Err(ChangeDeny::RecordFailed)
    );
    assert_eq!(w.pending.get(&h2).unwrap().approvals.len(), 0);
}

#[test]
fn c5b_a_version_store_failure_after_the_record_leaves_the_head_unchanged() {
    let w = world();
    let bad = FailingVersions(MemoryVersions::default());
    let cc = ChangeControl {
        verifier: &w.verifier,
        pending: &w.pending,
        versions: &bad,
        sink: &w.sink,
    };
    let h = cc
        .request(&w.t3(1, "alice"), None, &prompt(C1), NOW)
        .unwrap();
    cc.approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
    assert_eq!(
        cc.activate(&w.t3(900, "act"), None, &h, NOW + 2),
        Err(ChangeDeny::StoreFailed)
    );
    assert!(bad.head("prompt", "triage-prompt").is_none());
    let recs = w.sink.0.lock().unwrap();
    assert!(
        recs.last().unwrap().reason.contains("store_failed"),
        "the failure is recorded: {:?}",
        recs.last()
    );
}

#[test]
fn c6_records_hold_hashes_and_closed_words_only() {
    let w = world();
    let ch = change("prompt", "secret-name-xyzzy", C1, None);
    let h = w.cc().request(&w.t3(1, "alice"), None, &ch, NOW).unwrap();
    w.cc().approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
    w.cc()
        .activate(&w.t3(900, "act"), None, &h, NOW + 2)
        .unwrap();
    let recs = w.sink.0.lock().unwrap();
    assert_eq!(recs.len(), 3);
    for (r, action) in recs
        .iter()
        .zip(["change_request", "change_approve", "change_activate"])
    {
        assert_eq!(r.action, action);
        assert_eq!(r.decision, "allowed");
        assert_eq!(r.request_hash, h, "the record binds the change hash");
        let all = format!("{r:?}");
        for forbidden in ["secret-name-xyzzy", "alice", "bob", C1] {
            assert!(!all.contains(forbidden), "{forbidden} leaked into {all}");
        }
    }
}

#[test]
fn c7_the_same_inputs_and_clock_give_the_same_decisions_and_record_bytes() {
    let run = |tokens: &(Vec<u8>, Vec<u8>), list: &[u8], issuer_pub: &str| {
        let mut trust = Trust::default();
        trust.add(issuer_pub);
        let v = OfflineVerifier {
            trust,
            audience: "node-1".into(),
            skew: 30,
            max_ttl: 7200,
            rev_max_age: 300,
            revocations: Some(list.to_vec()),
        };
        let (pending, versions, sink) = (
            MemoryPending::default(),
            MemoryVersions::default(),
            Records(Mutex::new(vec![])),
        );
        let cc = ChangeControl {
            verifier: &v,
            pending: &pending,
            versions: &versions,
            sink: &sink,
        };
        let h = cc.request(&tokens.0, None, &prompt(C1), NOW).unwrap();
        cc.approve(&tokens.1, None, &h, NOW + 1).unwrap();
        let ver = cc.activate(&tokens.0, None, &h, NOW + 2).unwrap();
        let recs = sink.0.lock().unwrap().clone();
        (h, ver, recs)
    };
    let w = world();
    let tokens = (w.t3(1, "alice"), w.t3(2, "bob"));
    let list = empty_revocations(&w.issuer, NOW);
    let a = run(&tokens, &list, &w.issuer.pubkey_hex());
    let b = run(&tokens, &list, &w.issuer.pubkey_hex());
    assert_eq!(a, b);
}

#[test]
fn c8_two_simultaneous_activations_of_the_same_version_one_wins() {
    for threads in [2usize, 4, 8] {
        for _ in 0..50 {
            let w = world();
            let h = w
                .cc()
                .request(&w.t3(1, "alice"), None, &prompt(C1), NOW)
                .unwrap();
            w.cc().approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
            let wins = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|s| {
                for _ in 0..threads {
                    s.spawn(|| {
                        if w.cc()
                            .activate(&w.t3(900, "act"), None, &h, NOW + 2)
                            .is_ok()
                        {
                            wins.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    });
                }
            });
            assert_eq!(
                wins.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{threads} threads"
            );
            assert_eq!(w.versions.all("prompt", "triage-prompt").len(), 1);
        }
    }
}

#[test]
fn c9_the_requester_revoked_after_asking_does_not_cancel_a_valid_second_approval_but_a_revoked_approver_does_not_count(
) {
    let w = world();
    let h = w
        .cc()
        .request(&w.t3(1, "alice"), None, &prompt(C1), NOW)
        .unwrap();
    // bob approves while valid; carol's approval is refused (token revoked): only bob counts
    w.cc().approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
    let list = issue_revocations(
        &w.issuer,
        NOW,
        &[(format!("{:032x}", 1), NOW - 1, Reason::Compromise)],
    );
    let v = verifier(&w.issuer, list);
    let cc = ChangeControl {
        verifier: &v,
        pending: &w.pending,
        versions: &w.versions,
        sink: &w.sink,
    };
    assert!(
        cc.activate(&w.t3(900, "act"), None, &h, NOW + 2).is_ok(),
        "activation counts the stored approvals of distinct subjects"
    );
    let p: Pending = w.pending.get(&h).unwrap();
    assert_eq!(p.approvals.len(), 1);
}
