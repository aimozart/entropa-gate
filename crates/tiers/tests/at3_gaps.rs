//! AT3 bite-check gaps (tests only, new file so the red file stays untouched): behaviour that the first 14 tests did not pin and a hand mutation showed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_tiers::change::{
    Approval, Change, ChangeControl, ChangeDeny, MemoryPending, MemoryVersions, Pending,
    PendingStore,
};
use entropa_tiers::{RecordSink, TierRecord};

const NOW: u64 = 1_800_000_000;
struct Null;
impl RecordSink for Null {
    fn write(&self, _: &TierRecord) -> Result<(), String> {
        Ok(())
    }
}
#[test]
fn g1_an_approval_by_the_requester_found_in_the_store_does_not_count() {
    // approve() refuses a self-approval, but the store is a separate trust boundary: a stored approval carrying the requester's subject must still not satisfy activation
    let (issuer, v) = rig();
    let (pending, versions) = (MemoryPending::default(), MemoryVersions::default());
    let ch = Change {
        class: "prompt".into(),
        name: "p".into(),
        content_hash: "1".repeat(64),
        parent: None,
    };
    let h = ch.hash();
    pending
        .put(
            &h,
            Pending {
                change: ch,
                requester: "alice".into(),
                ts: NOW,
                approvals: vec![Approval {
                    subject: "alice".into(),
                    ts: NOW + 1,
                    token: vec![],
                    parent: None,
                }],
            },
        )
        .unwrap();
    let cc = ChangeControl {
        verifier: &v,
        pending: &pending,
        versions: &versions,
        sink: &Null,
    };
    assert_eq!(
        cc.activate(&t3(&issuer, 9, "carol"), None, &h, NOW + 2),
        Err(ChangeDeny::NotEnoughApprovals)
    );
    assert!(versions_empty(&versions));
}
fn versions_empty(v: &MemoryVersions) -> bool {
    use entropa_tiers::change::VersionStore;
    v.head("prompt", "p").is_none()
}

// ---- mutation triage (survivors of the first cargo-mutants run on change.rs), real tokens ----
use entropa_core::Probe;
use entropa_tiers::change::TTL;
use entropa_tiers::OfflineVerifier;
use entropa_tokens::{empty_revocations, issue_a, Claims, Tier, Trust};

fn rig() -> (Probe, OfflineVerifier) {
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    trust.add(&issuer.pubkey_hex());
    let v = OfflineVerifier {
        trust,
        audience: "node-1".into(),
        skew: 30,
        max_ttl: 7200,
        rev_max_age: 300,
        revocations: Some(empty_revocations(&issuer, NOW)),
    };
    (issuer, v)
}
fn t3(issuer: &Probe, id: u64, subject: &str) -> Vec<u8> {
    issue_a(
        issuer,
        &Claims {
            token_id: format!("{id:032x}"),
            subject: subject.into(),
            tier: Tier::T3,
            corpora: vec!["1".repeat(64)],
            actions: vec![
                "change:corpus".into(),
                "change:model".into(),
                "change:policy".into(),
                "change:prompt".into(),
            ],
            spend_cap: 1,
            rate_cap: 1,
            not_before: NOW - 10,
            expiry: NOW + 6000,
            audience: "node-1".into(),
            parent: None,
        },
    )
    .unwrap()
}
fn ch(name: &str) -> Change {
    Change {
        class: "prompt".into(),
        name: name.into(),
        content_hash: "1".repeat(64),
        parent: None,
    }
}

#[test]
fn g2_a_name_of_exactly_64_characters_is_accepted_and_65_is_not() {
    let (issuer, v) = rig();
    let (pending, versions) = (MemoryPending::default(), MemoryVersions::default());
    let cc = ChangeControl {
        verifier: &v,
        pending: &pending,
        versions: &versions,
        sink: &Null,
    };
    assert!(cc
        .request(&t3(&issuer, 1, "a"), None, &ch(&"n".repeat(64)), NOW)
        .is_ok());
    assert_eq!(
        cc.request(&t3(&issuer, 2, "a"), None, &ch(&"n".repeat(65)), NOW),
        Err(ChangeDeny::Malformed)
    );
}

#[test]
fn g3_a_live_request_cannot_be_taken_over_by_asking_again_but_an_expired_one_can_be_renewed() {
    let (issuer, v) = rig();
    let (pending, versions) = (MemoryPending::default(), MemoryVersions::default());
    let cc = ChangeControl {
        verifier: &v,
        pending: &pending,
        versions: &versions,
        sink: &Null,
    };
    let c = ch("p");
    let h = cc.request(&t3(&issuer, 1, "alice"), None, &c, NOW).unwrap();
    // bob asks for the very same change: he must not become the requester (that would let alice approve it)
    assert_eq!(
        cc.request(&t3(&issuer, 2, "bob"), None, &c, NOW + 1),
        Err(ChangeDeny::AlreadyRequested)
    );
    let at_ttl = OfflineVerifier {
        revocations: Some(empty_revocations(&issuer, NOW + TTL)),
        ..rig_like(&v)
    };
    let cc_ttl = ChangeControl {
        verifier: &at_ttl,
        pending: &pending,
        versions: &versions,
        sink: &Null,
    };
    assert_eq!(
        cc_ttl.request(&t3(&issuer, 2, "bob"), None, &c, NOW + TTL),
        Err(ChangeDeny::AlreadyRequested),
        "still live at exactly the TTL"
    );
    assert_eq!(pending.get(&h).unwrap().requester, "alice");
    // after the TTL the request has lapsed and may be renewed (approvals start again)
    let v2 = OfflineVerifier {
        revocations: Some(empty_revocations(&issuer, NOW + TTL + 1)),
        ..rig_like(&v)
    };
    let cc2 = ChangeControl {
        verifier: &v2,
        pending: &pending,
        versions: &versions,
        sink: &Null,
    };
    assert!(cc2
        .request(&t3(&issuer, 3, "bob"), None, &c, NOW + TTL + 1)
        .is_ok());
    assert_eq!(pending.get(&h).unwrap().requester, "bob");
}
fn rig_like(v: &OfflineVerifier) -> OfflineVerifier {
    OfflineVerifier {
        trust: v.trust.clone(),
        audience: v.audience.clone(),
        skew: v.skew,
        max_ttl: v.max_ttl,
        rev_max_age: v.rev_max_age,
        revocations: v.revocations.clone(),
    }
}

#[test]
fn g4_a_second_approval_by_the_same_subject_replaces_the_first_and_counts_once() {
    let (issuer, v) = rig();
    let (pending, versions) = (MemoryPending::default(), MemoryVersions::default());
    let cc = ChangeControl {
        verifier: &v,
        pending: &pending,
        versions: &versions,
        sink: &Null,
    };
    let h = cc
        .request(&t3(&issuer, 1, "alice"), None, &ch("p"), NOW)
        .unwrap();
    cc.approve(&t3(&issuer, 2, "bob"), None, &h, NOW + 1)
        .unwrap();
    cc.approve(&t3(&issuer, 3, "bob"), None, &h, NOW + 2)
        .unwrap();
    let ap = pending.get(&h).unwrap().approvals;
    assert_eq!(
        (ap.len(), ap[0].subject.as_str(), ap[0].ts),
        (1, "bob", NOW + 2)
    );
}

#[test]
fn g5_the_legacy_append_is_a_compare_and_set() {
    use entropa_tiers::change::{VersionRec, VersionStore};
    let versions = MemoryVersions::default();
    let v = |seq: u64, hash: &str, parent: Option<&str>| VersionRec {
        class: "prompt".into(),
        name: "p".into(),
        seq,
        content_hash: "1".repeat(64),
        parent_version_hash: parent.map(String::from),
        change_hash: "2".repeat(64),
        version_hash: hash.into(),
    };
    assert!(versions.append(v(1, "h1", None), None).is_ok());
    assert!(versions.head("prompt", "p").is_some(), "append must store");
    assert!(
        versions.append(v(2, "h2", None), None).is_err(),
        "head moved: expected none, head is h1"
    );
    assert!(
        versions.append(v(2, "h2", Some("zz")), Some("zz")).is_err(),
        "wrong expected head"
    );
    assert!(versions.append(v(2, "h2", Some("h1")), Some("h1")).is_ok());
    assert_eq!(versions.all("prompt", "p").len(), 2);
}

#[test]
fn g6_an_approver_holding_exactly_the_class_counts_and_one_holding_another_class_does_not() {
    let (issuer, v) = rig();
    let one = |id: u64, subject: &str, class: &str| {
        issue_a(
            &issuer,
            &Claims {
                token_id: format!("{id:032x}"),
                subject: subject.into(),
                tier: Tier::T3,
                corpora: vec!["1".repeat(64)],
                actions: vec![class.into()],
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
    let run = |class: &str| {
        let (pending, versions) = (MemoryPending::default(), MemoryVersions::default());
        let cc = ChangeControl {
            verifier: &v,
            pending: &pending,
            versions: &versions,
            sink: &Null,
        };
        let h = cc
            .request(&t3(&issuer, 1, "alice"), None, &ch("p"), NOW)
            .unwrap();
        let mut p = pending.get(&h).unwrap();
        p.approvals.push(Approval {
            subject: "bob".into(),
            ts: NOW + 1,
            token: one(2, "bob", class),
            parent: None,
        });
        pending.put(&h, p).unwrap();
        cc.activate(&t3(&issuer, 3, "carol"), None, &h, NOW + 2)
            .map(|_| ())
    };
    assert_eq!(run("change:prompt"), Ok(()), "exactly the class: counts");
    assert_eq!(
        run("change:corpus"),
        Err(ChangeDeny::NotEnoughApprovals),
        "another class: does not count"
    );
}
