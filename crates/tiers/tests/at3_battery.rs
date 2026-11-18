//! AT3 task 4: the planted-attack battery for change control, through the REAL parts: real signed tokens and verifier, real in-memory stores, real `LedgerSink` (signed evidence ledger,
//! rotated every 300 records because append replays the ledger, verified offline at the end). 18 attack classes x 300: a case counts as ACCEPTED if the attack leaves a sealed version
//! or its final call is Ok; each case must also end with the exact expected denial word. Control: 300 valid two-person changes, all activated. Seeds fixed; synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::adapters::LedgerSink;
use entropa_tiers::change::{
    Change, ChangeControl, ChangeDeny, MemoryPending, MemoryVersions, VersionStore, TTL,
};
use entropa_tiers::{OfflineVerifier, RecordSink, TierRecord};
use entropa_tokens::{
    empty_revocations, issue_a, issue_revocations, Claims, Deny, Reason, Tier, Trust,
};
use std::cell::{Cell, RefCell};

const NOW: u64 = 1_800_000_000;
const C1: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const C2: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const ALL: [&str; 4] = [
    "change:corpus",
    "change:model",
    "change:policy",
    "change:prompt",
];

/// A ledger sink that rotates to a new directory every 300 records.
struct Sw {
    dirs: RefCell<Vec<std::path::PathBuf>>,
    cur: RefCell<Option<LedgerSink>>,
    count: Cell<u32>,
    total: Cell<u32>,
    fail: Cell<bool>,
}
fn probe() -> Probe {
    Probe::from_signing_key_hex(&hex::encode(blake3::hash(b"at3-battery-key").as_bytes())).unwrap()
}
impl RecordSink for Sw {
    fn write(&self, r: &TierRecord) -> Result<(), String> {
        if self.fail.get() {
            return Err("disk full".into());
        }
        if self.count.get() >= 300 || self.cur.borrow().is_none() {
            let dir = std::env::temp_dir().join(format!(
                "at3-bat-{}-{}",
                std::process::id(),
                self.dirs.borrow().len()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            self.dirs.borrow_mut().push(dir.clone());
            *self.cur.borrow_mut() = Some(LedgerSink::new(dir, Box::new(probe())));
            self.count.set(0);
        }
        self.cur.borrow().as_ref().unwrap().write(r)?;
        self.count.set(self.count.get() + 1);
        self.total.set(self.total.get() + 1);
        Ok(())
    }
}

struct W {
    issuer: Probe,
    trust: Trust,
    verifier: OfflineVerifier,
    sink: Sw,
}
fn verifier(trust: &Trust, list: Vec<u8>, audience: &str) -> OfflineVerifier {
    OfflineVerifier {
        trust: trust.clone(),
        audience: audience.into(),
        skew: 30,
        max_ttl: 7200,
        rev_max_age: 300,
        revocations: Some(list),
    }
}
fn world() -> W {
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    assert!(!trust.add(&issuer.pubkey_hex()).is_empty());
    let v = verifier(&trust, empty_revocations(&issuer, NOW), "node-1");
    W {
        issuer,
        trust,
        verifier: v,
        sink: Sw {
            dirs: RefCell::new(vec![]),
            cur: RefCell::new(None),
            count: Cell::new(0),
            total: Cell::new(0),
            fail: Cell::new(false),
        },
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
impl W {
    fn tok(&self, id: u64, subject: &str, tier: Tier, actions: &[&str]) -> Vec<u8> {
        issue_a(&self.issuer, &claims(id, subject, tier, actions)).unwrap()
    }
    fn t3(&self, id: u64, subject: &str) -> Vec<u8> {
        self.tok(id, subject, Tier::T3, &ALL)
    }
}
fn change(i: usize, content: &str, parent: Option<&str>) -> Change {
    Change {
        class: ["prompt", "corpus", "policy", "model"][i % 4].into(),
        name: format!("item-{i}"),
        content_hash: content.into(),
        parent: parent.map(String::from),
    }
}

/// One attack case: the stores are fresh; the closure returns the final result of the attack and the denial word it must end with.
type Case = (Result<(), ChangeDeny>, ChangeDeny);
fn run_class(
    name: &str,
    n: usize,
    w: &W,
    mut one: impl FnMut(usize, &ChangeControl<'_>, &MemoryVersions) -> Case,
) -> usize {
    let mut accepted = 0;
    for i in 0..n {
        let (pending, versions) = (MemoryPending::default(), MemoryVersions::default());
        let cc = ChangeControl {
            verifier: &w.verifier,
            pending: &pending,
            versions: &versions,
            sink: &w.sink,
        };
        let (res, want) = one(i, &cc, &versions);
        let sealed: usize = (0..4)
            .map(|k| {
                versions
                    .all(
                        ["prompt", "corpus", "policy", "model"][k],
                        &format!("item-{i}"),
                    )
                    .len()
            })
            .sum();
        let sealed_extra: usize = (0..4)
            .map(|k| {
                versions
                    .all(
                        ["prompt", "corpus", "policy", "model"][k],
                        &format!("item-{}", i + 1_000_000),
                    )
                    .len()
            })
            .sum();
        if res.is_ok() || sealed_extra > 0 || (sealed > 0 && want != ChangeDeny::HeadMoved) {
            accepted += 1;
            eprintln!("ACCEPTED {name} case {i}");
        } else {
            assert_eq!(
                res,
                Err(want),
                "{name} case {i} was denied for another reason"
            );
        }
    }
    eprintln!("{name}: {accepted} accepted of {n}");
    accepted
}
fn base(w: &W, cc: &ChangeControl<'_>, i: usize, k: u64) -> (String, Change) {
    let c = change(i, C1, None);
    let h = cc
        .request(&w.t3(k + 1, &format!("req-{i}")), None, &c, NOW)
        .unwrap();
    (h, c)
}

#[test]
fn battery_300_per_class_18_classes_0_activated_and_300_valid_changes_activated() {
    let n = 300;
    let w = world();
    let id = |i: usize, k: u64| 10_000_000 * k + 10 * i as u64;
    let mut total = 0;

    total += run_class("single_approver", n, &w, |i, cc, _| {
        let (h, _) = base(&w, cc, i, id(i, 1));
        (
            cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 1)
                .map(|_| ()),
            ChangeDeny::NotEnoughApprovals,
        )
    });
    total += run_class("self_approval", n, &w, |i, cc, _| {
        let (h, _) = base(&w, cc, i, id(i, 2));
        let r = cc.approve(&w.t3(id(i, 2) + 1, &format!("req-{i}")), None, &h, NOW + 1);
        assert_eq!(r, Err(ChangeDeny::SelfApproval));
        (
            cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
                .map(|_| ()),
            ChangeDeny::NotEnoughApprovals,
        )
    });
    total += run_class("same_subject_two_tokens", n, &w, |i, cc, _| {
        let (h, _) = base(&w, cc, i, id(i, 3));
        for k in 2..4 {
            assert_eq!(
                cc.approve(&w.t3(id(i, 3) + k, &format!("req-{i}")), None, &h, NOW + 1),
                Err(ChangeDeny::SelfApproval)
            );
        }
        (
            cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
                .map(|_| ()),
            ChangeDeny::NotEnoughApprovals,
        )
    });
    total += run_class("approval_for_another_hash", n, &w, |i, cc, _| {
        let (hx, _) = base(&w, cc, i, id(i, 4));
        let other = change(i, C2, None);
        let hy = cc
            .request(
                &w.t3(id(i, 4) + 5, &format!("req-{i}")),
                None,
                &Change {
                    name: format!("item-{i}-b"),
                    ..other
                },
                NOW,
            )
            .unwrap();
        cc.approve(&w.t3(id(i, 4) + 6, "approver"), None, &hx, NOW + 1)
            .unwrap();
        (
            cc.activate(
                &w.t3(77_000_000 + i as u64, "activator"),
                None,
                &hy,
                NOW + 2,
            )
            .map(|_| ()),
            ChangeDeny::NotEnoughApprovals,
        )
    });
    total += run_class("expired_approval", n, &w, |i, cc, _| {
        let (h, _) = base(&w, cc, i, id(i, 5));
        cc.approve(&w.t3(id(i, 5) + 2, "approver"), None, &h, NOW + 1)
            .unwrap();
        // late activation: the revocation list must be issued at that time (authenticated activation)
        let at = NOW + 1 + TTL + 1 + (i as u64 % 100);
        let late = verifier(&w.trust, empty_revocations(&w.issuer, at), "node-1");
        let cc2 = ChangeControl {
            verifier: &late,
            pending: cc.pending,
            versions: cc.versions,
            sink: cc.sink,
        };
        (
            cc2.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, at)
                .map(|_| ()),
            ChangeDeny::ApprovalExpired,
        )
    });
    total += run_class("approval_by_lower_tier", n, &w, |i, cc, _| {
        let (h, _) = base(&w, cc, i, id(i, 6));
        let tier = [Tier::T0, Tier::T1, Tier::T2][i % 3];
        assert_eq!(
            cc.approve(
                &w.tok(id(i, 6) + 2, "approver", tier, &ALL),
                None,
                &h,
                NOW + 1
            ),
            Err(ChangeDeny::NotT3)
        );
        (
            cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
                .map(|_| ()),
            ChangeDeny::NotEnoughApprovals,
        )
    });
    total += run_class("revoked_approver", n, &w, |i, cc, _| {
        let (h, _) = base(&w, cc, i, id(i, 7));
        let c = claims(id(i, 7) + 2, "approver", Tier::T3, &ALL);
        let t = issue_a(&w.issuer, &c).unwrap();
        let list = issue_revocations(
            &w.issuer,
            NOW,
            &[(
                c.token_id.clone(),
                NOW - 5,
                [Reason::Compromise, Reason::Requested, Reason::Superseded][i % 3],
            )],
        );
        let v = verifier(&w.trust, list, "node-1");
        let cc2 = ChangeControl {
            verifier: &v,
            pending: cc.pending,
            versions: cc.versions,
            sink: cc.sink,
        };
        assert_eq!(
            cc2.approve(&t, None, &h, NOW + 1),
            Err(ChangeDeny::Token(Deny::Revoked))
        );
        (
            cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
                .map(|_| ()),
            ChangeDeny::NotEnoughApprovals,
        )
    });
    total += run_class("replayed_activation", n, &w, |i, cc, ver| {
        let (h, c) = base(&w, cc, i, id(i, 8));
        cc.approve(&w.t3(id(i, 8) + 2, "approver"), None, &h, NOW + 1)
            .unwrap();
        cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
            .unwrap();
        let again = cc
            .activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 3)
            .map(|_| ());
        assert_eq!(
            ver.all(&c.class, &c.name).len(),
            1,
            "a replay must not append"
        );
        (again, ChangeDeny::HeadMoved)
    });
    total += run_class("class_not_in_token", n, &w, |i, cc, _| {
        let c = change(i, C1, None);
        let only_other: &[&str] = if c.class == "prompt" {
            &["change:corpus"]
        } else {
            &["change:prompt"]
        };
        (
            cc.request(
                &w.tok(id(i, 9) + 1, "req", Tier::T3, only_other),
                None,
                &c,
                NOW,
            )
            .map(|_| ()),
            ChangeDeny::ClassNotInToken,
        )
    });
    total += run_class("version_overwrite", n, &w, |i, cc, ver| {
        let (h, c) = base(&w, cc, i, id(i, 10));
        cc.approve(&w.t3(id(i, 10) + 2, "approver"), None, &h, NOW + 1)
            .unwrap();
        cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
            .unwrap();
        let again = Change {
            content_hash: C2.into(),
            ..c.clone()
        }; // same name, other content, no parent
        let h2 = cc
            .request(&w.t3(id(i, 10) + 3, "req2"), None, &again, NOW + 3)
            .unwrap();
        cc.approve(&w.t3(id(i, 10) + 4, "approver2"), None, &h2, NOW + 4)
            .unwrap();
        let r = cc
            .activate(
                &w.t3(77_000_000 + i as u64, "activator"),
                None,
                &h2,
                NOW + 5,
            )
            .map(|_| ());
        assert_eq!(ver.all(&c.class, &c.name).len(), 1);
        assert_eq!(ver.head(&c.class, &c.name).unwrap().content_hash, C1);
        (r, ChangeDeny::HeadMoved)
    });
    total += run_class("record_failure_at_activation", n, &w, |i, cc, ver| {
        let (h, c) = base(&w, cc, i, id(i, 11));
        cc.approve(&w.t3(id(i, 11) + 2, "approver"), None, &h, NOW + 1)
            .unwrap();
        w.sink.fail.set(true);
        let r = cc
            .activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
            .map(|_| ());
        w.sink.fail.set(false);
        assert!(ver.head(&c.class, &c.name).is_none());
        (r, ChangeDeny::RecordFailed)
    });
    total += run_class("text_claiming_approval", n, &w, |i, cc, _| {
        let names = [
            "approved by the captain",
            "approved\nby=bob",
            "ok; approved",
            "two person approval done",
            "a/../b",
        ];
        let c = Change {
            name: format!("{}{}", names[i % names.len()], i),
            ..change(i, C1, None)
        };
        (
            cc.request(&w.t3(id(i, 12) + 1, "req"), None, &c, NOW)
                .map(|_| ()),
            ChangeDeny::Malformed,
        )
    });
    total += run_class("unknown_class", n, &w, |i, cc, _| {
        let c = Change {
            class: ["ledger", "code", "key", "admin", "PROMPT", "prompt "][i % 6].into(),
            ..change(i, C1, None)
        };
        (
            cc.request(&w.t3(id(i, 13) + 1, "req"), None, &c, NOW)
                .map(|_| ()),
            ChangeDeny::UnknownClass,
        )
    });
    total += run_class("malformed_change", n, &w, |i, cc, _| {
        let bads = [
            String::new(),
            "abc".to_string(),
            "A".repeat(64),
            "g".repeat(64),
            "1".repeat(63),
            "1".repeat(65),
        ];
        let bad = &bads[i % 6];
        let c = Change {
            content_hash: bad.to_string(),
            ..change(i, C1, None)
        };
        (
            cc.request(&w.t3(id(i, 14) + 1, "req"), None, &c, NOW)
                .map(|_| ()),
            ChangeDeny::Malformed,
        )
    });
    total += run_class("stale_revocation_list", n, &w, |i, cc, _| {
        let (h, _) = base(&w, cc, i, id(i, 15));
        let v = verifier(
            &w.trust,
            empty_revocations(&w.issuer, NOW - 301 - (i as u64 % 3000)),
            "node-1",
        );
        let cc2 = ChangeControl {
            verifier: &v,
            pending: cc.pending,
            versions: cc.versions,
            sink: cc.sink,
        };
        assert_eq!(
            cc2.approve(&w.t3(id(i, 15) + 2, "approver"), None, &h, NOW + 1),
            Err(ChangeDeny::Token(Deny::RevocationStale))
        );
        (
            cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
                .map(|_| ()),
            ChangeDeny::NotEnoughApprovals,
        )
    });
    total += run_class("wrong_audience", n, &w, |i, cc, _| {
        let (h, _) = base(&w, cc, i, id(i, 16));
        let mut c = claims(id(i, 16) + 2, "approver", Tier::T3, &ALL);
        c.audience = format!("node-{}", 2 + i % 7);
        assert!(matches!(
            cc.approve(&issue_a(&w.issuer, &c).unwrap(), None, &h, NOW + 1),
            Err(ChangeDeny::Token(_))
        ));
        (
            cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
                .map(|_| ()),
            ChangeDeny::NotEnoughApprovals,
        )
    });
    total += run_class("widened_token", n, &w, |i, cc, _| {
        let (h, _) = base(&w, cc, i, id(i, 17));
        let mut pc = claims(id(i, 17) + 2, "approver", Tier::T3, &["change:prompt"]);
        pc.actions = vec!["change:prompt".into()];
        let parent = issue_a(&w.issuer, &pc).unwrap();
        let mut c = claims(
            id(i, 17) + 3,
            "approver",
            Tier::T3,
            &["change:policy", "change:prompt"],
        ); // wider than the parent
        c.parent = Some(pc.token_id.clone());
        assert!(matches!(
            cc.approve(&issue_a(&w.issuer, &c).unwrap(), Some(&parent), &h, NOW + 1),
            Err(ChangeDeny::Token(_))
        ));
        (
            cc.activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
                .map(|_| ()),
            ChangeDeny::NotEnoughApprovals,
        )
    });
    total += run_class("stale_head_parent_mismatch", n, &w, |i, cc, ver| {
        let (h, c) = base(&w, cc, i, id(i, 18));
        cc.approve(&w.t3(id(i, 18) + 2, "approver"), None, &h, NOW + 1)
            .unwrap();
        let v1 = cc
            .activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
            .unwrap();
        let c2 = Change {
            content_hash: C2.into(),
            parent: Some(v1.version_hash.clone()),
            ..c.clone()
        };
        let h2 = cc
            .request(&w.t3(id(i, 18) + 3, "req2"), None, &c2, NOW + 3)
            .unwrap();
        // a rival change on the same parent is activated first
        let rival = Change {
            content_hash: "3".repeat(64),
            parent: Some(v1.version_hash.clone()),
            ..c.clone()
        };
        let h3 = cc
            .request(&w.t3(id(i, 18) + 4, "req3"), None, &rival, NOW + 3)
            .unwrap();
        cc.approve(&w.t3(id(i, 18) + 5, "approver2"), None, &h3, NOW + 4)
            .unwrap();
        cc.activate(
            &w.t3(77_000_000 + i as u64, "activator"),
            None,
            &h3,
            NOW + 5,
        )
        .unwrap();
        cc.approve(&w.t3(id(i, 18) + 6, "approver3"), None, &h2, NOW + 6)
            .unwrap();
        let r = cc
            .activate(
                &w.t3(77_000_000 + i as u64, "activator"),
                None,
                &h2,
                NOW + 7,
            )
            .map(|_| ());
        assert_eq!(ver.all(&c.class, &c.name).len(), 2, "only v1 and the rival");
        (r, ChangeDeny::HeadMoved)
    });
    assert_eq!(total, 0, "attacks were accepted");
    let bound = 1.0 - 0.05f64.powf(1.0 / n as f64);
    assert!(bound < 0.01);
    eprintln!("95 percent upper bound per class (0 accepted of 300): {bound:.4}");

    // control: 300 valid two-person changes, all activated, each three signed records
    let before = w.sink.total.get();
    let mut activated = 0;
    for i in 0..n {
        let (pending, versions) = (MemoryPending::default(), MemoryVersions::default());
        let cc = ChangeControl {
            verifier: &w.verifier,
            pending: &pending,
            versions: &versions,
            sink: &w.sink,
        };
        let (h, c) = base(&w, &cc, i, id(i, 20));
        cc.approve(
            &w.t3(id(i, 20) + 2, &format!("appr-{i}")),
            None,
            &h,
            NOW + 1,
        )
        .unwrap();
        if cc
            .activate(&w.t3(77_000_000 + i as u64, "activator"), None, &h, NOW + 2)
            .is_ok()
            && versions.head(&c.class, &c.name).is_some()
        {
            activated += 1;
        }
    }
    assert_eq!(activated, n, "valid changes were refused");
    assert_eq!(
        w.sink.total.get() - before,
        3 * n as u32,
        "three records per valid change"
    );
    // every ledger directory verifies offline
    let pubkey = probe().pubkey_hex();
    let mut records = 0u32;
    for d in w.sink.dirs.borrow().iter() {
        let out = entropa_platinum::verify_evidence_with(d, &pubkey).unwrap();
        records += out
            .split("records=")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .parse::<u32>()
            .unwrap();
    }
    assert_eq!(
        records,
        w.sink.total.get(),
        "the ledgers verify offline and hold every record written"
    );
    eprintln!(
        "ledger directories verified: {}, records {records}",
        w.sink.dirs.borrow().len()
    );
}
