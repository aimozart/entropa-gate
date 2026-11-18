//! The replay harness for the "prove" step: pure, deterministic, hash-checked.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::Value;

struct Rule(Box<dyn Fn(&str) -> ReplayVerdict>);
impl Decider for Rule {
    fn decide(&self, input: &str) -> ReplayVerdict {
        (self.0)(input)
    }
}

fn item(id: &str, input: &str, bad: bool) -> ReplayItem {
    ReplayItem {
        id: id.into(),
        input: input.into(),
        input_hash: input_hash(input),
        bad_outcome: bad,
    }
}
fn items() -> Vec<ReplayItem> {
    vec![
        item("d-1", "read:1", false),
        item("d-2", "write:2", false),
        item("d-3", "write:3", true),
        item("d-4", "read:4", false),
        item("d-5", "delete:5", true),
        item("d-6", "delete:6", false),
    ]
}
/// The current policy: everything except delete:6 is allowed.
fn current() -> Rule {
    Rule(Box::new(|i| {
        if i == "delete:6" {
            ReplayVerdict::Deny
        } else {
            ReplayVerdict::Allow
        }
    }))
}
/// Candidate A: also denies every write and delete.
fn candidate_a() -> Rule {
    Rule(Box::new(|i| {
        if i.starts_with("read") {
            ReplayVerdict::Allow
        } else {
            ReplayVerdict::Deny
        }
    }))
}
/// Candidate B: denies writes only, allows deletes.
fn candidate_b() -> Rule {
    Rule(Box::new(|i| {
        if i.starts_with("write") {
            ReplayVerdict::Deny
        } else {
            ReplayVerdict::Allow
        }
    }))
}

#[test]
fn x1_counts_for_a_stricter_candidate() {
    let r = must(replay(&items(), &current(), &candidate_a()));
    assert_eq!(
        (r.replayed, r.changed, r.newly_denied, r.newly_allowed),
        (6, 3, 3, 0)
    );
    assert_eq!(r.changed_ids, vec!["d-2", "d-3", "d-5"]);
    assert_eq!(
        (r.bad_denied, r.bad_allowed),
        (2, 0),
        "both bad-outcome decisions are now denied"
    );
}

#[test]
fn x2_counts_for_a_candidate_that_also_loosens() {
    let r = must(replay(&items(), &current(), &candidate_b()));
    assert_eq!(
        (r.replayed, r.changed, r.newly_denied, r.newly_allowed),
        (6, 3, 2, 1)
    );
    assert_eq!(r.changed_ids, vec!["d-2", "d-3", "d-6"]);
    assert_eq!(
        (r.bad_denied, r.bad_allowed),
        (1, 1),
        "write:3 is denied, delete:5 still allowed"
    );
}

#[test]
fn x3_the_same_policy_changes_nothing_and_no_requests_is_an_empty_report() {
    let r = must(replay(&items(), &current(), &current()));
    assert_eq!(
        (
            r.changed,
            r.newly_denied,
            r.newly_allowed,
            r.changed_ids.len()
        ),
        (0, 0, 0, 0)
    );
    let e = must(replay(&[], &current(), &candidate_a()));
    assert_eq!(
        (e.replayed, e.changed, e.bad_denied, e.bad_allowed),
        (0, 0, 0, 0)
    );
}

#[test]
fn x4_an_input_that_does_not_match_its_recorded_hash_is_refused() {
    let mut it = items();
    it[2].input = "write:3 and more".into();
    assert_eq!(
        expect_err(replay(&it, &current(), &candidate_a())),
        CouncilError::HashMismatch("d-3".into())
    );
    let mut it = items();
    it[0].input_hash = "0".repeat(64);
    assert_eq!(
        expect_err(replay(&it, &current(), &candidate_a())),
        CouncilError::HashMismatch("d-1".into())
    );
}

#[test]
fn x5_the_replay_is_deterministic_and_independent_of_the_order_of_the_requests() {
    let a = must(replay(&items(), &current(), &candidate_b()));
    let mut rev = items();
    rev.reverse();
    let b = must(replay(&rev, &current(), &candidate_b()));
    assert_eq!(a, b);
}

#[test]
fn x6_the_input_hash_matches_an_independent_implementation() {
    let v: Value = serde_json::from_str(include_str!("vectors/council_v1.json")).unwrap();
    assert_eq!(
        input_hash(v["replay_input"]["input"].as_str().unwrap()),
        v["replay_input"]["hash"].as_str().unwrap()
    );
    assert_ne!(input_hash("a"), input_hash("b"));
}

#[test]
fn x7_duplicate_ids_are_refused() {
    let mut it = items();
    it.push(item("d-1", "read:99", false));
    assert!(matches!(
        expect_err(replay(&it, &current(), &candidate_a())),
        CouncilError::Invalid(_)
    ));
}
