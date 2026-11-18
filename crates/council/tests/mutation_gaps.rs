//! Tests added after the first mutation run of S12c: boundaries, untested event types and golden lines that the
//! 80 + 22 tests did not pin (docs/evidence/s12c-mutants-run1.txt lists the survivors these answer).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::json;

// ---- event invariants -------------------------------------------------------------------------------------------

#[test]
fn m1_a_session_opened_event_needs_a_real_period_and_an_expiry_after_its_own_time() {
    let ts = NOW + 100;
    let bad = [
        json!({"period_start": NOW, "period_end": NOW}),
        json!({"expires": ts}),
        json!({"expires": ts - 1}),
    ];
    for over in bad {
        assert!(
            matches!(
                decode_event(&payload("session.opened", over.clone())),
                Err(CouncilError::Invalid(_))
            ),
            "{over}"
        );
    }
    must(decode_event(&payload(
        "session.opened",
        json!({"period_start": NOW, "period_end": NOW + 1, "expires": ts + 1}),
    )));
}

#[test]
fn m2_an_evaluation_cannot_report_a_hindsight_gap_over_one_hundred_points() {
    assert!(matches!(
        decode_event(&payload(
            "evaluation.recorded",
            json!({"hindsight_gap_pp": 101})
        )),
        Err(CouncilError::Invalid(_))
    ));
    must(decode_event(&payload(
        "evaluation.recorded",
        json!({"hindsight_gap_pp": 100}),
    )));
}

#[test]
fn m3_a_precedent_reference_names_exactly_k_ids() {
    assert!(matches!(
        decode_event(&payload(
            "precedent.referenced",
            json!({"k": 3, "precedent_ids": ["p1", "p2"]})
        )),
        Err(CouncilError::Invalid(_))
    ));
    assert!(matches!(
        decode_event(&payload(
            "precedent.referenced",
            json!({"k": 2, "precedent_ids": ["p1", "p2", "p3"]})
        )),
        Err(CouncilError::Invalid(_))
    ));
    must(decode_event(&payload(
        "precedent.referenced",
        json!({"k": 5, "precedent_ids": ["a", "b", "c", "d", "e"]}),
    )));
}

// ---- planted-fault harness --------------------------------------------------------------------------------------

fn pair_suite() -> Suite {
    let c = |id: &str, bad: bool| Case {
        id: id.into(),
        kind: CaseKind::Hindsight {
            pair_id: id[..2].into(),
            outcome_bad: bad,
        },
        valid_refs: vec!["e1".into()],
    };
    Suite {
        cases: vec![
            c("h1a", true),
            c("h1b", false),
            c("h2a", true),
            c("h2b", false),
        ],
    }
}
fn flagged(id: &str, yes: bool) -> Output {
    Output {
        case_id: id.into(),
        findings: if yes {
            vec![Finding {
                class: "policy_gap".into(),
                refs: vec!["e1".into()],
            }]
        } else {
            vec![]
        },
        rerun: None,
    }
}

#[test]
fn m4_the_hindsight_gap_is_one_hundred_when_only_one_side_of_every_pair_is_flagged() {
    let only_bad = [
        flagged("h1a", true),
        flagged("h1b", false),
        flagged("h2a", true),
        flagged("h2b", false),
    ];
    assert_eq!(
        must(evaluate(&pair_suite(), &only_bad)).hindsight_gap_pp,
        Some(100)
    );
    let only_good = [
        flagged("h1a", false),
        flagged("h1b", true),
        flagged("h2a", false),
        flagged("h2b", true),
    ];
    assert_eq!(
        must(evaluate(&pair_suite(), &only_good)).hindsight_gap_pp,
        Some(100),
        "the gap is a difference, in either direction"
    );
    let none = [
        flagged("h1a", false),
        flagged("h1b", false),
        flagged("h2a", false),
        flagged("h2b", false),
    ];
    assert_eq!(
        must(evaluate(&pair_suite(), &none)).hindsight_gap_pp,
        Some(0)
    );
}

// ---- provenance --------------------------------------------------------------------------------------------------

#[test]
fn m5_an_entry_id_is_the_session_prefix_and_the_finding_up_to_exactly_sixty_four_characters() {
    let fits = "f".repeat(47);
    let e = must(admit(
        &ev("decision.recorded", json!({"finding_id": fits})),
        true,
        true,
    ));
    assert_eq!(e.id.len(), 64);
    assert!(e.id.ends_with(&fits));
    let too_long = "f".repeat(48);
    let e = must(admit(
        &ev("decision.recorded", json!({"finding_id": too_long})),
        true,
        true,
    ));
    assert!(e.id.len() <= 64 && e.id.starts_with("h:"), "{}", e.id);
}

#[test]
fn m6_an_index_needs_a_valid_model_id_and_a_valid_normalisation_each_on_its_own() {
    let ok = |m: ModelDescriptor| Index::build(m, vec![("a".into(), vec![1.0, 0.0, 0.0])]);
    let base = ModelDescriptor {
        id: "test-embed".into(),
        dim: 3,
        normalization: "unit".into(),
    };
    must(ok(base.clone()));
    assert!(matches!(
        ok(ModelDescriptor {
            id: "has space".into(),
            ..base.clone()
        }),
        Err(CouncilError::Invalid(_))
    ));
    assert!(matches!(
        ok(ModelDescriptor {
            normalization: "not valid".into(),
            ..base.clone()
        }),
        Err(CouncilError::Invalid(_))
    ));
    assert!(matches!(
        ok(ModelDescriptor {
            id: String::new(),
            ..base
        }),
        Err(CouncilError::Invalid(_))
    ));
}

#[test]
fn m7_exactly_five_hits_make_a_valid_reference_and_six_do_not() {
    let model = ModelDescriptor {
        id: "test-embed".into(),
        dim: 2,
        normalization: "unit".into(),
    };
    let entries: Vec<(String, Vec<f32>)> = (1..=6)
        .map(|i| (format!("p{i}"), vec![1.0, i as f32]))
        .collect();
    let idx = must(Index::build(model, entries));
    let five = must(idx.search(&[1.0, 1.0], 5));
    assert_eq!(five.len(), 5);
    must(precedent_reference(
        &idx,
        "idx:1",
        &five,
        "yes",
        "0123456789abcdef",
        NOW,
    ));
    let mut six = five.clone();
    six.push(Hit {
        id: "p6".into(),
        score: 0.0,
    });
    assert!(matches!(
        precedent_reference(&idx, "idx:1", &six, "yes", "0123456789abcdef", NOW),
        Err(CouncilError::Limit(_))
    ));
}

// ---- rendering ---------------------------------------------------------------------------------------------------

#[test]
fn m8_rebuttals_and_outcomes_render_as_documented() {
    let r = must(render_for_model(&[ev("rebuttal.submitted", json!({}))]));
    assert_eq!(
        r,
        "rebuttal f-1 stance=disagree counter=policy_intended evidence=none\n"
    );
    let with_ev = must(render_for_model(&[ev(
        "rebuttal.submitted",
        json!({"evidence": [{"kind": "ledger_index", "ref": "idx:1"}, {"kind": "precedent_id", "ref": "p9"}]}),
    )]));
    assert_eq!(with_ev, "rebuttal f-1 stance=disagree counter=policy_intended evidence=ledger_index:idx:1,precedent_id:p9\n");
    let o = must(render_for_model(&[ev("outcome.recorded", json!({}))]));
    assert_eq!(
        o,
        "outcome idx:1 outcome=as_intended delay=3600 source=scenario_label\n"
    );
}

// ---- session -----------------------------------------------------------------------------------------------------

#[test]
fn m9_the_quorum_is_valid_only_when_all_three_parts_are_present() {
    for bits in 0..8u8 {
        let q = Quorum {
            critic_report: bits & 1 != 0,
            rebuttals_complete: bits & 2 != 0,
            recommendation_complete: bits & 4 != 0,
        };
        assert_eq!(q.valid(), bits == 7, "{q:?}");
    }
}

#[test]
fn m10_a_change_is_linked_only_to_an_accepted_decision_with_that_change() {
    let link = |kind: &str, finding: &str| {
        ev(
            "change.linked",
            json!({"finding_id": finding, "change_kind": kind, "ref": "commit-1"}),
        )
    };
    let mut s = to_awaiting_decision(2);
    assert!(
        matches!(
            expect_err(s.apply(&link("test", "f-1"), Role::Builder, NOW + 500)),
            CouncilError::Invalid(_)
        ),
        "no decision yet"
    );
    must(decide(
        &mut s,
        1,
        json!({"approval_ref": "appr-1"}),
        NOW + 501,
    ));
    must(decide(
        &mut s,
        2,
        json!({"decision": "reject", "reason": "out_of_scope", "change_kind": "none", "approval_ref": null}),
        NOW + 502,
    ));
    assert!(
        matches!(
            expect_err(s.apply(&link("lesson", "f-1"), Role::Builder, NOW + 503)),
            CouncilError::Invalid(_)
        ),
        "another kind of change"
    );
    assert!(
        matches!(
            expect_err(s.apply(&link("test", "f-2"), Role::Builder, NOW + 503)),
            CouncilError::Invalid(_)
        ),
        "a rejected finding"
    );
    assert_eq!(
        expect_err(s.apply(&link("test", "f-1"), Role::Critic, NOW + 503)),
        CouncilError::WrongRole
    );
    must(s.apply(&link("test", "f-1"), Role::Builder, NOW + 504));
}

#[test]
fn m11_a_proof_names_a_finding_of_this_session_and_comes_from_the_scheduler() {
    let mut s = to_awaiting_decision(1);
    let proof = |id: &str| ev("proof.recorded", json!({"finding_id": id}));
    must(s.apply(&proof("f-1"), Role::Scheduler, NOW + 500));
    assert_eq!(
        expect_err(s.apply(&proof("f-9"), Role::Scheduler, NOW + 500)),
        CouncilError::Incomplete
    );
    assert_eq!(
        expect_err(s.apply(&proof("f-1"), Role::Builder, NOW + 500)),
        CouncilError::WrongRole
    );
}

#[test]
fn m12_a_report_may_cover_twelve_findings_and_never_more() {
    let mut s = open_session();
    for i in 1..=12 {
        must(s.apply(&finding(i), Role::Critic, NOW + 1));
    }
    let report = |n: u64| {
        ev(
            "report.submitted",
            json!({"n_findings": n, "findings_hash": findings_hash(&ids(12))}),
        )
    };
    assert!(matches!(
        expect_err(s.apply(&report(13), Role::Critic, NOW + 2)),
        CouncilError::Limit(_)
    ));
    assert!(matches!(
        expect_err(s.apply(&report(14), Role::Critic, NOW + 2)),
        CouncilError::Limit(_)
    ));
    must(s.apply(&report(12), Role::Critic, NOW + 2));
}

#[test]
fn m13_expired_pending_needs_something_pending() {
    let mut s = to_awaiting_decision(1);
    must(decide(
        &mut s,
        1,
        json!({"approval_ref": "appr-1"}),
        NOW + 500,
    ));
    let all_done = ev(
        "session.expired",
        json!({"closing": "expired_pending", "accepted": 1, "rejected": 0, "deferred": 0, "pending": 0}),
    );
    assert_eq!(
        expect_err(s.apply(&all_done, Role::Scheduler, EXPIRES)),
        CouncilError::Incomplete,
        "nothing is pending: it closes as all_decided, not as expired_pending"
    );
}

#[test]
fn m14_an_accepted_decision_without_a_change_approves_nothing() {
    let mut s = to_awaiting_decision(2);
    must(decide(
        &mut s,
        1,
        json!({"change_kind": "none", "approval_ref": "appr-1"}),
        NOW + 500,
    ));
    must(decide(
        &mut s,
        2,
        json!({"approval_ref": "appr-2"}),
        NOW + 501,
    ));
    let a = s.approved_changes();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].finding_id, "f-2");
}
