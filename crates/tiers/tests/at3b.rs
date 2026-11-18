//! AT3b red tests (a stage record (not published)): V1 a revoked approver does not count; V2 an expired approver token or a stale revocation list at activation denies; V3 activation needs a valid
//! T3 token naming the class; V4 a lost race writes exactly one `allowed` activation record; V5 a record failure aborts the reservation; V6 the activator's token hash is recorded;
//! V7 a tampered stored approval is not counted; battery class `revoked_after_approving` x 300 with a control of 300. Tokens are real. Expected words written by hand.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::change::{
    Approval, Change, ChangeControl, ChangeDeny, MemoryPending, MemoryVersions, PendingStore,
    VersionStore,
};
use entropa_tiers::{OfflineVerifier, RecordSink, TierRecord};
use entropa_tokens::{
    empty_revocations, issue_a, issue_revocations, Claims, Deny, Reason, Tier, Trust,
};
use std::sync::Mutex;

const NOW: u64 = 1_800_000_000;
const C1: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
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
struct FlakySink {
    fail: Mutex<bool>,
    inner: Records,
}
impl RecordSink for FlakySink {
    fn write(&self, r: &TierRecord) -> Result<(), String> {
        if *self.fail.lock().unwrap() {
            return Err("disk full".into());
        }
        self.inner.write(r)
    }
}

struct W {
    issuer: Probe,
    trust: Trust,
}
fn w() -> W {
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    assert!(!trust.add(&issuer.pubkey_hex()).is_empty());
    W { issuer, trust }
}
impl W {
    /// A verifier whose revocation list was issued at `at` and revokes `revoked` (token id, reason).
    fn verifier(&self, at: u64, revoked: &[(u64, Reason)]) -> OfflineVerifier {
        let list = if revoked.is_empty() {
            empty_revocations(&self.issuer, at)
        } else {
            let entries: Vec<(String, u64, Reason)> = revoked
                .iter()
                .map(|(id, r)| (format!("{id:032x}"), at.saturating_sub(1), *r))
                .collect();
            issue_revocations(&self.issuer, at, &entries)
        };
        OfflineVerifier {
            trust: self.trust.clone(),
            audience: "node-1".into(),
            skew: 30,
            max_ttl: 7200,
            rev_max_age: 300,
            revocations: Some(list),
        }
    }
    fn tok(&self, id: u64, subject: &str, tier: Tier, actions: &[&str], expiry: u64) -> Vec<u8> {
        issue_a(
            &self.issuer,
            &Claims {
                token_id: format!("{id:032x}"),
                subject: subject.into(),
                tier,
                corpora: vec![C1.into()],
                actions: actions.iter().map(|s| s.to_string()).collect(),
                spend_cap: 1,
                rate_cap: 1,
                not_before: NOW - 10,
                expiry,
                audience: "node-1".into(),
                parent: None,
            },
        )
        .unwrap()
    }
    fn t3(&self, id: u64, subject: &str) -> Vec<u8> {
        self.tok(id, subject, Tier::T3, &ALL, NOW + 6000)
    }
}
fn change(name: &str) -> Change {
    Change {
        class: "prompt".into(),
        name: name.into(),
        content_hash: C1.into(),
        parent: None,
    }
}
fn stores() -> (MemoryPending, MemoryVersions, Records) {
    (
        MemoryPending::default(),
        MemoryVersions::default(),
        Records(Mutex::new(vec![])),
    )
}

#[test]
fn v1_an_approver_revoked_after_approving_does_not_count() {
    let w = w();
    let (pending, versions, sink) = stores();
    let v0 = w.verifier(NOW, &[]);
    let cc0 = ChangeControl {
        verifier: &v0,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    let h = cc0
        .request(&w.t3(1, "alice"), None, &change("p"), NOW)
        .unwrap();
    cc0.approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
    // bob's token (id 2) is revoked at NOW+100; the list in force at activation is fresh and names it
    let v1 = w.verifier(NOW + 100, &[(2, Reason::Compromise)]);
    let cc1 = ChangeControl {
        verifier: &v1,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    assert_eq!(
        cc1.activate(&w.t3(3, "carol"), None, &h, NOW + 110),
        Err(ChangeDeny::Token(Deny::Revoked))
    );
    assert!(versions.head("prompt", "p").is_none());
    // a second, valid approver is enough
    cc1.approve(&w.t3(4, "dave"), None, &h, NOW + 120).unwrap();
    assert!(
        cc1.activate(&w.t3(3, "carol"), None, &h, NOW + 130).is_ok(),
        "dave alone counts; bob stays refused"
    );
}

#[test]
fn v2_an_approver_token_expired_at_activation_or_a_stale_list_denies() {
    let w = w();
    let (pending, versions, sink) = stores();
    let v0 = w.verifier(NOW, &[]);
    let cc0 = ChangeControl {
        verifier: &v0,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    let h = cc0
        .request(&w.t3(1, "alice"), None, &change("p"), NOW)
        .unwrap();
    // bob's token lives only until NOW+200
    cc0.approve(
        &w.tok(2, "bob", Tier::T3, &ALL, NOW + 200),
        None,
        &h,
        NOW + 1,
    )
    .unwrap();
    // fresh list, activator valid, bob's token expired
    let v1 = w.verifier(NOW + 500, &[]);
    let cc1 = ChangeControl {
        verifier: &v1,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    assert_eq!(
        cc1.activate(&w.t3(3, "carol"), None, &h, NOW + 500),
        Err(ChangeDeny::Token(Deny::Expired))
    );
    // stale list (issued at NOW, used at NOW+400): the whole activation is refused
    assert_eq!(
        cc0.activate(&w.t3(3, "carol"), None, &h, NOW + 400),
        Err(ChangeDeny::Token(Deny::RevocationStale))
    );
    assert!(versions.head("prompt", "p").is_none());
}

#[test]
fn v3_activation_needs_a_valid_t3_token_naming_the_class() {
    let w = w();
    let (pending, versions, sink) = stores();
    let v = w.verifier(NOW, &[]);
    let cc = ChangeControl {
        verifier: &v,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    let h = cc
        .request(&w.t3(1, "alice"), None, &change("p"), NOW)
        .unwrap();
    cc.approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
    assert!(matches!(
        cc.activate(b"junk", None, &h, NOW + 2),
        Err(ChangeDeny::Token(_))
    ));
    assert_eq!(
        cc.activate(
            &w.tok(5, "carol", Tier::T2, &ALL, NOW + 6000),
            None,
            &h,
            NOW + 2
        ),
        Err(ChangeDeny::NotT3)
    );
    assert_eq!(
        cc.activate(
            &w.tok(6, "carol", Tier::T3, &["change:corpus"], NOW + 6000),
            None,
            &h,
            NOW + 2
        ),
        Err(ChangeDeny::ClassNotInToken)
    );
    assert!(
        matches!(
            cc.activate(
                &w.tok(7, "carol", Tier::T3, &ALL, NOW + 100),
                None,
                &h,
                NOW + 200
            ),
            Err(ChangeDeny::Token(_))
        ),
        "expired activator"
    );
    let v_rev = w.verifier(NOW, &[(8, Reason::Requested)]);
    let cc_rev = ChangeControl {
        verifier: &v_rev,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    assert_eq!(
        cc_rev.activate(&w.t3(8, "carol"), None, &h, NOW + 2),
        Err(ChangeDeny::Token(Deny::Revoked))
    );
    assert!(versions.head("prompt", "p").is_none());
    assert!(cc.activate(&w.t3(9, "carol"), None, &h, NOW + 3).is_ok());
}

#[test]
fn v4_a_lost_race_writes_exactly_one_allowed_activation_record() {
    for threads in [2usize, 4, 8] {
        for _ in 0..40 {
            let w = w();
            let (pending, versions, sink) = stores();
            let v = w.verifier(NOW, &[]);
            let cc = ChangeControl {
                verifier: &v,
                pending: &pending,
                versions: &versions,
                sink: &sink,
            };
            let h = cc
                .request(&w.t3(1, "alice"), None, &change("p"), NOW)
                .unwrap();
            cc.approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
            let acts: Vec<Vec<u8>> = (0..threads).map(|i| w.t3(10 + i as u64, "carol")).collect();
            std::thread::scope(|s| {
                for a in &acts {
                    s.spawn(|| {
                        let cc = ChangeControl {
                            verifier: &v,
                            pending: &pending,
                            versions: &versions,
                            sink: &sink,
                        };
                        let _ = cc.activate(a, None, &h, NOW + 2);
                    });
                }
            });
            let recs = sink.0.lock().unwrap();
            let allowed = recs
                .iter()
                .filter(|r| r.action == "change_activate" && r.decision == "allowed")
                .count();
            let denied = recs
                .iter()
                .filter(|r| r.action == "change_activate" && r.decision == "denied")
                .count();
            assert_eq!(
                allowed, 1,
                "{threads} threads: one allowed activation record"
            );
            assert_eq!(
                denied,
                threads - 1,
                "{threads} threads: every loser wrote one denial and nothing else"
            );
            assert_eq!(versions.all("prompt", "p").len(), 1);
        }
    }
}

#[test]
fn v5_a_record_failure_aborts_the_reservation_so_a_retry_succeeds() {
    let w = w();
    let (pending, versions, _) = stores();
    let sink = FlakySink {
        fail: Mutex::new(false),
        inner: Records(Mutex::new(vec![])),
    };
    let v = w.verifier(NOW, &[]);
    let cc = ChangeControl {
        verifier: &v,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    let h = cc
        .request(&w.t3(1, "alice"), None, &change("p"), NOW)
        .unwrap();
    cc.approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
    *sink.fail.lock().unwrap() = true;
    assert_eq!(
        cc.activate(&w.t3(3, "carol"), None, &h, NOW + 2),
        Err(ChangeDeny::RecordFailed)
    );
    assert!(versions.head("prompt", "p").is_none());
    *sink.fail.lock().unwrap() = false;
    assert!(
        cc.activate(&w.t3(3, "carol"), None, &h, NOW + 3).is_ok(),
        "the failed attempt must not leave the place held"
    );
}

#[test]
fn v6_the_activation_record_names_the_activator_by_hash_only() {
    let w = w();
    let (pending, versions, sink) = stores();
    let v = w.verifier(NOW, &[]);
    let cc = ChangeControl {
        verifier: &v,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    let h = cc
        .request(&w.t3(1, "alice"), None, &change("p"), NOW)
        .unwrap();
    cc.approve(&w.t3(2, "bob"), None, &h, NOW + 1).unwrap();
    cc.activate(&w.t3(3, "carol-the-activator"), None, &h, NOW + 2)
        .unwrap();
    let recs = sink.0.lock().unwrap();
    let last = recs.last().unwrap();
    assert_eq!(last.action, "change_activate");
    let want = hex::encode(blake3::hash(format!("{:032x}", 3).as_bytes()).as_bytes());
    assert_eq!(last.token_hash.as_deref(), Some(want.as_str()));
    assert!(!format!("{last:?}").contains("carol"));
}

#[test]
fn v7_a_stored_approval_whose_subject_differs_from_its_token_is_not_counted() {
    let w = w();
    let (pending, versions, sink) = stores();
    let v = w.verifier(NOW, &[]);
    let cc = ChangeControl {
        verifier: &v,
        pending: &pending,
        versions: &versions,
        sink: &sink,
    };
    let h = cc
        .request(&w.t3(1, "alice"), None, &change("p"), NOW)
        .unwrap();
    let mut p = pending.get(&h).unwrap();
    // bob's real token, filed under the name "mallory"; and an approval with no token at all
    p.approvals.push(Approval {
        subject: "mallory".into(),
        ts: NOW + 1,
        token: w.t3(2, "bob"),
        parent: None,
    });
    p.approvals.push(Approval {
        subject: "erin".into(),
        ts: NOW + 1,
        token: vec![],
        parent: None,
    });
    pending.put(&h, p).unwrap();
    assert!(cc.activate(&w.t3(3, "carol"), None, &h, NOW + 2).is_err());
    assert!(versions.head("prompt", "p").is_none());
}

#[test]
fn b1_battery_revoked_after_approving_300_none_activated_and_300_valid_activated() {
    let w = w();
    let mut revoked_ok = 0;
    for i in 0..300u64 {
        let (pending, versions, sink) = stores();
        let v0 = w.verifier(NOW, &[]);
        let cc0 = ChangeControl {
            verifier: &v0,
            pending: &pending,
            versions: &versions,
            sink: &sink,
        };
        let c = Change {
            class: ["prompt", "corpus", "policy", "model"][i as usize % 4].into(),
            name: format!("item-{i}"),
            content_hash: C1.into(),
            parent: None,
        };
        let id = 100_000 + 10 * i;
        let h = cc0.request(&w.t3(id, "alice"), None, &c, NOW).unwrap();
        cc0.approve(&w.t3(id + 1, "bob"), None, &h, NOW + 1)
            .unwrap();
        // bob is revoked 1 to 3,000 s after approving, with each reason; the activation list is fresh
        let when = NOW + 2 + 1 + (i * 10) % 3000;
        let reason = [Reason::Compromise, Reason::Requested, Reason::Superseded][i as usize % 3];
        let v1 = w.verifier(when, &[(id + 1, reason)]);
        let cc1 = ChangeControl {
            verifier: &v1,
            pending: &pending,
            versions: &versions,
            sink: &sink,
        };
        let r = cc1.activate(&w.t3(id + 2, "carol"), None, &h, when);
        assert_eq!(
            r.map(|_| ()),
            Err(ChangeDeny::Token(Deny::Revoked)),
            "case {i}"
        );
        assert!(
            versions.head(&c.class, &c.name).is_none(),
            "case {i}: activated"
        );
        // the control: the same change with a second approver who is not revoked activates
        cc1.approve(&w.t3(id + 3, "dave"), None, &h, when).unwrap();
        if cc1.activate(&w.t3(id + 2, "carol"), None, &h, when).is_ok() {
            revoked_ok += 1;
        }
    }
    assert_eq!(
        revoked_ok, 300,
        "valid second approvers must still activate"
    );
}
