//! Surplus findings carry over to the next weekly session, in a stable order, as a recorded event
//! (decision 3 of the S12b review; the council design notes section 18).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::json;

fn cand(id: &str, severity: &str) -> Candidate {
    Candidate {
        id: id.into(),
        severity: severity.into(),
    }
}

/// 15 candidates: ids f-01..f-15; severities spread so that ties on severity are broken by id.
fn fifteen() -> Vec<Candidate> {
    let sev = [
        "low",
        "high",
        "medium",
        "hard_rule",
        "low",
        "high",
        "medium",
        "low",
        "high",
        "medium",
        "low",
        "hard_rule",
        "low",
        "medium",
        "high",
    ];
    sev.iter()
        .enumerate()
        .map(|(i, s)| cand(&format!("f-{:02}", i + 1), s))
        .collect()
}

#[test]
fn k1_the_surplus_is_the_lowest_ranked_in_a_stable_order() {
    let p = must(plan_carryover(&fifteen(), 12));
    // order: hard_rule (f-04, f-12), high (f-02, f-06, f-09, f-15), medium (f-03, f-07, f-10, f-14), low (f-01, f-05, f-08, f-11, f-13)
    assert_eq!(
        p.in_session,
        vec![
            "f-04", "f-12", "f-02", "f-06", "f-09", "f-15", "f-03", "f-07", "f-10", "f-14", "f-01",
            "f-05"
        ]
    );
    assert_eq!(p.carried, vec!["f-08", "f-11", "f-13"]);
}

#[test]
fn k2_the_plan_does_not_depend_on_the_order_of_the_input() {
    let base = must(plan_carryover(&fifteen(), 12));
    let mut rev = fifteen();
    rev.reverse();
    assert_eq!(must(plan_carryover(&rev, 12)), base);
    let mut rot = fifteen();
    rot.rotate_left(7);
    assert_eq!(must(plan_carryover(&rot, 12)), base);
}

#[test]
fn k3_nothing_is_carried_when_everything_fits_and_the_cap_is_exact() {
    let ten: Vec<Candidate> = fifteen().into_iter().take(10).collect();
    let p = must(plan_carryover(&ten, 12));
    assert_eq!((p.in_session.len(), p.carried.len()), (10, 0));
    let twelve: Vec<Candidate> = fifteen().into_iter().take(12).collect();
    assert_eq!(
        must(plan_carryover(&twelve, 12)).carried.len(),
        0,
        "exactly the cap: nothing carried"
    );
    let thirteen: Vec<Candidate> = fifteen().into_iter().take(13).collect();
    assert_eq!(must(plan_carryover(&thirteen, 12)).carried.len(), 1);
    assert_eq!(
        must(plan_carryover(&[], 12)),
        Carryover {
            in_session: vec![],
            carried: vec![]
        }
    );
}

#[test]
fn k4_the_plan_refuses_duplicates_unknown_severities_and_a_zero_cap() {
    let mut dup = fifteen();
    dup.push(cand("f-01", "low"));
    assert!(matches!(
        expect_err(plan_carryover(&dup, 12)),
        CouncilError::Invalid(_)
    ));
    let mut sev = fifteen();
    sev[0].severity = "urgent".into();
    assert!(matches!(
        expect_err(plan_carryover(&sev, 12)),
        CouncilError::Invalid(_)
    ));
    assert!(matches!(
        expect_err(plan_carryover(&fifteen(), 0)),
        CouncilError::Invalid(_)
    ));
    let mut bad_id = fifteen();
    bad_id[0].id = "has space".into();
    assert!(matches!(
        expect_err(plan_carryover(&bad_id, 12)),
        CouncilError::Invalid(_)
    ));
}

#[test]
fn k5_the_event_schema_is_closed_and_consistent() {
    let e = ev("carryover.recorded", json!({}));
    assert_eq!(e.event_type(), "carryover.recorded");
    let ids: Vec<String> = (1..=65).map(|i| format!("f-{i}")).collect();
    let cases = [
        json!({"carried_ids": ids, "n_candidates": 100}),
        json!({"carried_hash": "xyz"}),
        json!({"n_candidates": 1}),
        json!({"carried_ids": ["has space"]}),
        json!({"to_period_start": "later"}),
        json!({"extra": 1}),
    ];
    for over in cases {
        assert!(
            matches!(
                decode_event(&payload("carryover.recorded", over.clone())),
                Err(CouncilError::Invalid(_))
            ),
            "{over}"
        );
    }
}

fn after_report() -> Session {
    let mut s = open_session();
    must(s.apply(&finding(1), Role::Critic, NOW + 1));
    must(s.apply(&ev("report.submitted", json!({})), Role::Critic, NOW + 2));
    s
}

#[test]
fn k6_the_session_records_the_carry_over_once_after_the_report() {
    let mut s = after_report();
    must(s.apply(
        &ev("carryover.recorded", json!({})),
        Role::Orchestrator,
        NOW + 3,
    ));
    assert_eq!(s.carried(), vec!["f-13", "f-14"], "in the recorded order");
    assert_eq!(
        expect_err(s.apply(
            &ev("carryover.recorded", json!({})),
            Role::Orchestrator,
            NOW + 4
        )),
        CouncilError::OutOfOrder,
        "only once"
    );
}

#[test]
fn k7_the_carry_over_is_refused_before_the_report_with_a_wrong_hash_or_role_or_collision() {
    let mut early = open_session();
    assert_eq!(
        expect_err(early.apply(
            &ev("carryover.recorded", json!({})),
            Role::Orchestrator,
            NOW + 1
        )),
        CouncilError::OutOfOrder
    );
    let mut s = after_report();
    let wrong_hash = ev("carryover.recorded", json!({"carried_hash": hex64('7')}));
    assert_eq!(
        expect_err(s.apply(&wrong_hash, Role::Orchestrator, NOW + 3)),
        CouncilError::Incomplete
    );
    assert_eq!(
        expect_err(s.apply(&ev("carryover.recorded", json!({})), Role::Critic, NOW + 3)),
        CouncilError::WrongRole
    );
    assert_eq!(
        expect_err(s.apply(&ev("carryover.recorded", json!({})), Role::Human, NOW + 3)),
        CouncilError::WrongRole
    );
    let collide_ids = ["f-1".to_string(), "f-14".to_string()];
    let collide = ev(
        "carryover.recorded",
        json!({"carried_ids": collide_ids, "carried_hash": findings_hash(&collide_ids)}),
    );
    assert_eq!(
        expect_err(s.apply(&collide, Role::Orchestrator, NOW + 3)),
        CouncilError::Duplicate,
        "a carried id is already a finding of this session"
    );
    assert!(s.carried().is_empty(), "a refused event changes nothing");
}

#[test]
fn k8_the_carry_over_does_not_change_the_quorum_or_approve_anything() {
    let mut s = to_awaiting_decision(1);
    must(s.apply(
        &ev("carryover.recorded", json!({})),
        Role::Orchestrator,
        NOW + 500,
    ));
    assert!(s.quorum().valid());
    assert!(s.approved_changes().is_empty());
}
