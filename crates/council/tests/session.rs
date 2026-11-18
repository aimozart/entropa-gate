//! The session state machine and the quorum rule (docs/ARCHITECTURE-COUNCIL.md sections 4 and 5).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::json;

#[test]
fn s1_a_session_walks_every_state_in_order() {
    let mut s = open_session();
    assert_eq!(s.state(NOW + 10), SessionState::CollectingFindings);
    must(s.apply(&finding(1), Role::Critic, NOW + 100));
    must(s.apply(&finding(2), Role::Critic, NOW + 100));
    assert_eq!(s.state(NOW + 100), SessionState::CollectingFindings);
    assert_eq!(
        s.quorum(),
        Quorum {
            critic_report: false,
            rebuttals_complete: false,
            recommendation_complete: false
        }
    );
    must(s.apply(
        &ev(
            "report.submitted",
            json!({"n_findings": 2, "findings_hash": findings_hash(&ids(2))}),
        ),
        Role::Critic,
        NOW + 200,
    ));
    assert_eq!(s.state(NOW + 200), SessionState::CollectingRebuttals);
    must(s.apply(
        &ev("rebuttal.submitted", json!({"finding_id": "f-1"})),
        Role::Contestor,
        NOW + 300,
    ));
    assert_eq!(s.state(NOW + 300), SessionState::CollectingRebuttals);
    must(s.apply(
        &ev("rebuttal.submitted", json!({"finding_id": "f-2"})),
        Role::Contestor,
        NOW + 300,
    ));
    assert_eq!(s.state(NOW + 300), SessionState::PacketReady);
    assert!(
        s.quorum().critic_report
            && s.quorum().rebuttals_complete
            && !s.quorum().recommendation_complete
    );
    let items = json!([{"finding_id":"f-1","check":"verified","recommendation":"accept"},{"finding_id":"f-2","check":"verified","recommendation":"reject"}]);
    must(s.apply(
        &ev(
            "packet.compiled",
            json!({"item_count": 2, "findings_hash": findings_hash(&ids(2)), "items": items}),
        ),
        Role::Orchestrator,
        NOW + 400,
    ));
    assert_eq!(s.state(NOW + 400), SessionState::AwaitingDecision);
    assert!(s.quorum().valid());
    must(decide(&mut s, 1, json!({}), NOW + 500));
    assert_eq!(s.state(NOW + 500), SessionState::AwaitingDecision);
    must(decide(
        &mut s,
        2,
        json!({"decision":"reject","reason":"evidence_insufficient","change_kind":"none","approval_ref":null}),
        NOW + 600,
    ));
    assert_eq!(s.state(NOW + 600), SessionState::Decided);
    must(s.apply(
        &ev(
            "session.closed",
            json!({"closing":"all_decided","accepted":1,"rejected":1,"deferred":0,"pending":0}),
        ),
        Role::Scheduler,
        NOW + 700,
    ));
    assert_eq!(s.state(NOW + 700), SessionState::Closed);
}

#[test]
fn s2_events_out_of_order_are_refused() {
    let mut s = open_session();
    assert_eq!(
        expect_err(s.apply(
            &ev("rebuttal.submitted", json!({})),
            Role::Contestor,
            NOW + 1
        )),
        CouncilError::OutOfOrder,
        "rebuttal before any finding"
    );
    must(s.apply(&finding(1), Role::Critic, NOW + 2));
    assert_eq!(
        expect_err(s.apply(
            &ev("rebuttal.submitted", json!({})),
            Role::Contestor,
            NOW + 3
        )),
        CouncilError::OutOfOrder,
        "rebuttal before the report"
    );
    assert_eq!(
        expect_err(decide(&mut s, 1, json!({}), NOW + 3)),
        CouncilError::OutOfOrder,
        "decision before the packet"
    );
    let packet = ev("packet.compiled", json!({}));
    assert_eq!(
        expect_err(s.apply(&packet, Role::Orchestrator, NOW + 3)),
        CouncilError::OutOfOrder,
        "packet before the report"
    );
    must(s.apply(&ev("report.submitted", json!({})), Role::Critic, NOW + 4));
    assert_eq!(
        expect_err(s.apply(&finding(2), Role::Critic, NOW + 5)),
        CouncilError::OutOfOrder,
        "a finding after the report"
    );
    assert_eq!(
        expect_err(s.apply(&packet, Role::Orchestrator, NOW + 5)),
        CouncilError::OutOfOrder,
        "packet before the rebuttals"
    );
    assert_eq!(
        expect_err(s.apply(&ev("report.submitted", json!({})), Role::Critic, NOW + 5)),
        CouncilError::Duplicate,
        "a second report"
    );
    assert_eq!(
        expect_err(s.apply(&ev("session.opened", json!({})), Role::Scheduler, NOW + 5)),
        CouncilError::OutOfOrder,
        "opening twice"
    );
}

#[test]
fn s3_every_event_type_refuses_the_wrong_role() {
    let mut s = to_awaiting_decision(1);
    let cases: Vec<(&str, Role)> = vec![
        ("finding.submitted", Role::Contestor),
        ("finding.submitted", Role::Human),
        ("report.submitted", Role::Orchestrator),
        ("rebuttal.submitted", Role::Critic),
        ("packet.compiled", Role::Human),
        ("packet.compiled", Role::Critic),
        ("decision.recorded", Role::Orchestrator),
        ("decision.recorded", Role::Builder),
        ("decision.recorded", Role::Critic),
        ("decision.recorded", Role::Scheduler),
        ("session.closed", Role::Human),
        ("session.closed", Role::Orchestrator),
    ];
    for (kind, role) in cases {
        let e = ev(kind, json!({}));
        assert_eq!(
            expect_err(s.apply(&e, role, NOW + 500)),
            CouncilError::WrongRole,
            "{kind} by {role:?}"
        );
    }
    assert_eq!(
        expect_err(Session::open(
            &ev("session.opened", json!({})),
            Role::Critic,
            &scope().0
        )),
        CouncilError::WrongRole
    );
    assert_eq!(
        expect_err(Session::open(
            &ev("session.opened", json!({})),
            Role::Human,
            &scope().0
        )),
        CouncilError::WrongRole
    );
}

#[test]
fn s4_wrong_session_duplicates_and_session_less_events() {
    let mut s = open_session();
    assert_eq!(
        expect_err(s.apply(
            &ev("finding.submitted", json!({"session_id": OTHER_SID})),
            Role::Critic,
            NOW + 1
        )),
        CouncilError::WrongSession
    );
    must(s.apply(&finding(1), Role::Critic, NOW + 2));
    assert_eq!(
        expect_err(s.apply(&finding(1), Role::Critic, NOW + 3)),
        CouncilError::Duplicate,
        "same finding id twice"
    );
    assert!(
        matches!(
            expect_err(s.apply(&ev("outcome.recorded", json!({})), Role::Generator, NOW + 3)),
            CouncilError::Invalid(_)
        ),
        "not a session event"
    );
    must(s.apply(&ev("report.submitted", json!({})), Role::Critic, NOW + 4));
    must(s.apply(
        &ev("rebuttal.submitted", json!({})),
        Role::Contestor,
        NOW + 5,
    ));
    assert_eq!(
        expect_err(s.apply(
            &ev("rebuttal.submitted", json!({})),
            Role::Contestor,
            NOW + 6
        )),
        CouncilError::Duplicate,
        "same rebuttal twice"
    );
    must(s.apply(
        &ev("packet.compiled", json!({})),
        Role::Orchestrator,
        NOW + 7,
    ));
    must(decide(&mut s, 1, json!({}), NOW + 8));
    assert_eq!(
        expect_err(decide(
            &mut s,
            1,
            json!({"decision":"reject","reason":"out_of_scope","change_kind":"none","approval_ref":null}),
            NOW + 9
        )),
        CouncilError::Duplicate,
        "same decision twice: the first stands"
    );
}

#[test]
fn s5_the_independence_rule_is_enforced_in_code() {
    let mut s = open_session();
    let f = |over| ev("finding.submitted", over);
    // idx:1 and idx:2 were decided by Nova-based agents, idx:3 and idx:4 by Gemini-based agents.
    assert_eq!(
        expect_err(s.apply(
            &f(json!({"finding_id":"a","provider":"bedrock","subject_ref":"idx:1"})),
            Role::Critic,
            NOW + 1
        )),
        CouncilError::Independence,
        "a Nova critic about a Nova decision"
    );
    assert_eq!(
        expect_err(s.apply(
            &f(json!({"finding_id":"b","provider":"vertex","subject_ref":"idx:3"})),
            Role::Critic,
            NOW + 1
        )),
        CouncilError::Independence,
        "a Gemini critic about a Gemini decision"
    );
    must(s.apply(
        &f(json!({"finding_id":"c","provider":"vertex","subject_ref":"idx:1"})),
        Role::Critic,
        NOW + 1,
    ));
    must(s.apply(
        &f(json!({"finding_id":"d","provider":"bedrock","subject_ref":"idx:3"})),
        Role::Critic,
        NOW + 1,
    ));
    must(s.apply(
        &f(json!({"finding_id":"e","provider":"fake","subject_ref":"idx:1"})),
        Role::Critic,
        NOW + 1,
    ));
    assert!(
        matches!(
            expect_err(s.apply(
                &f(json!({"finding_id":"g","subject_ref":"idx:99"})),
                Role::Critic,
                NOW + 1
            )),
            CouncilError::Invalid(_)
        ),
        "a subject outside the window"
    );
    must(s.apply(&ev("report.submitted", json!({"n_findings": 3, "findings_hash": findings_hash(&["c".to_string(), "d".to_string(), "e".to_string()])})), Role::Critic, NOW + 2));
    let r = |id: &str, provider: &str| {
        ev(
            "rebuttal.submitted",
            json!({"finding_id": id, "provider": provider}),
        )
    };
    assert_eq!(
        expect_err(s.apply(&r("c", "vertex"), Role::Contestor, NOW + 3)),
        CouncilError::Independence,
        "the contestor shares the critic's family"
    );
    assert_eq!(
        expect_err(s.apply(&r("d", "bedrock"), Role::Contestor, NOW + 3)),
        CouncilError::Independence
    );
    must(s.apply(&r("c", "bedrock"), Role::Contestor, NOW + 3));
    must(s.apply(&r("d", "vertex"), Role::Contestor, NOW + 3));
    must(s.apply(&r("e", "fake"), Role::Contestor, NOW + 3));
}

#[test]
fn s6_the_window_hash_binds_the_scope() {
    let good = scope().0;
    must(Session::open(
        &ev("session.opened", json!({})),
        Role::Scheduler,
        &good,
    ));
    let mut fewer = good.clone();
    fewer.decisions.pop();
    assert_eq!(
        expect_err(Session::open(
            &ev("session.opened", json!({})),
            Role::Scheduler,
            &fewer
        )),
        CouncilError::WindowMismatch,
        "a decision left out"
    );
    let mut more = good.clone();
    more.decisions.push(("idx:5".into(), Provider::Bedrock));
    assert_eq!(
        expect_err(Session::open(
            &ev("session.opened", json!({})),
            Role::Scheduler,
            &more
        )),
        CouncilError::WindowMismatch,
        "a decision added"
    );
    assert_eq!(
        expect_err(Session::open(
            &ev("session.opened", json!({"window_hash": hex64('9')})),
            Role::Scheduler,
            &good
        )),
        CouncilError::WindowMismatch
    );
    assert_eq!(
        expect_err(Session::open(
            &ev("session.opened", json!({"n_decisions": 5})),
            Role::Scheduler,
            &good
        )),
        CouncilError::WindowMismatch
    );
}

#[test]
fn s7_the_report_and_the_packet_must_be_complete() {
    // report counts and hash
    let mut s = open_session();
    must(s.apply(&finding(1), Role::Critic, NOW + 1));
    assert_eq!(
        expect_err(s.apply(
            &ev(
                "report.submitted",
                json!({"n_findings": 2, "findings_hash": findings_hash(&ids(2))})
            ),
            Role::Critic,
            NOW + 2
        )),
        CouncilError::Incomplete,
        "report claims a finding that was never submitted"
    );
    assert_eq!(
        expect_err(s.apply(
            &ev("report.submitted", json!({"findings_hash": hex64('7')})),
            Role::Critic,
            NOW + 2
        )),
        CouncilError::Incomplete,
        "report hash does not cover the submitted findings"
    );
    // packet that drops a finding, adds one, or lacks a recommendation
    let mut s = open_session();
    for i in 1..=2 {
        must(s.apply(&finding(i), Role::Critic, NOW + 1));
    }
    must(s.apply(
        &ev(
            "report.submitted",
            json!({"n_findings": 2, "findings_hash": findings_hash(&ids(2))}),
        ),
        Role::Critic,
        NOW + 2,
    ));
    for i in 1..=2 {
        must(s.apply(
            &ev(
                "rebuttal.submitted",
                json!({"finding_id": format!("f-{i}")}),
            ),
            Role::Contestor,
            NOW + 3,
        ));
    }
    let item =
        |id: &str| json!({"finding_id": id, "check": "verified", "recommendation": "accept"});
    let packet = |n: usize, hash: Vec<String>, items: Vec<serde_json::Value>| {
        ev(
            "packet.compiled",
            json!({"item_count": n, "findings_hash": findings_hash(&hash), "items": items}),
        )
    };
    assert_eq!(
        expect_err(s.apply(
            &packet(1, ids(1), vec![item("f-1")]),
            Role::Orchestrator,
            NOW + 4
        )),
        CouncilError::Incomplete,
        "a finding dropped from the packet"
    );
    assert_eq!(
        expect_err(s.apply(
            &packet(1, ids(2), vec![item("f-1")]),
            Role::Orchestrator,
            NOW + 4
        )),
        CouncilError::Incomplete,
        "hash covers both but an item is missing"
    );
    assert_eq!(
        expect_err(s.apply(
            &packet(2, ids(2), vec![item("f-1"), item("f-9")]),
            Role::Orchestrator,
            NOW + 4
        )),
        CouncilError::Incomplete,
        "an item for an unknown finding"
    );
    assert_eq!(
        expect_err(s.apply(
            &packet(2, ids(2), vec![item("f-1"), item("f-1")]),
            Role::Orchestrator,
            NOW + 4
        )),
        CouncilError::Incomplete,
        "an item twice"
    );
    must(s.apply(
        &packet(2, ids(2), vec![item("f-2"), item("f-1")]),
        Role::Orchestrator,
        NOW + 4,
    ));
}

#[test]
fn s8_a_session_holds_at_most_twelve_findings() {
    let mut s = open_session();
    for i in 1..=12 {
        must(s.apply(&finding(i), Role::Critic, NOW + 1));
    }
    assert!(matches!(
        expect_err(s.apply(&finding(13), Role::Critic, NOW + 1)),
        CouncilError::Limit(_)
    ));
}

#[test]
fn s9_a_rebuttal_or_decision_for_an_unknown_finding_is_refused() {
    let mut s = open_session();
    must(s.apply(&finding(1), Role::Critic, NOW + 1));
    must(s.apply(&ev("report.submitted", json!({})), Role::Critic, NOW + 2));
    assert_eq!(
        expect_err(s.apply(
            &ev("rebuttal.submitted", json!({"finding_id": "f-9"})),
            Role::Contestor,
            NOW + 3
        )),
        CouncilError::Incomplete
    );
    must(s.apply(
        &ev("rebuttal.submitted", json!({})),
        Role::Contestor,
        NOW + 3,
    ));
    must(s.apply(
        &ev("packet.compiled", json!({})),
        Role::Orchestrator,
        NOW + 4,
    ));
    assert_eq!(
        expect_err(decide(&mut s, 9, json!({}), NOW + 5)),
        CouncilError::Incomplete
    );
}

#[test]
fn s10_decision_rules_attestation_approval_and_hard_rule_items() {
    // a hard-rule finding
    let hard = |s: &mut Session| {
        must(s.apply(
            &ev("finding.submitted", json!({"severity": "hard_rule"})),
            Role::Critic,
            NOW + 1,
        ));
        must(s.apply(&ev("report.submitted", json!({})), Role::Critic, NOW + 2));
        must(s.apply(
            &ev("rebuttal.submitted", json!({})),
            Role::Contestor,
            NOW + 3,
        ));
        must(s.apply(
            &ev("packet.compiled", json!({})),
            Role::Orchestrator,
            NOW + 4,
        ));
    };
    let mut s = open_session();
    hard(&mut s);
    assert_eq!(
        expect_err(decide(
            &mut s,
            1,
            json!({"attested": true, "auth_ref": hex64('d')}),
            NOW + 5
        )),
        CouncilError::AttestationNotAccepted,
        "an attestation can never decide a hard-rule item"
    );
    assert_eq!(
        expect_err(decide(
            &mut s,
            1,
            json!({"attested": false, "auth_ref": null}),
            NOW + 5
        )),
        CouncilError::AttestationNotAccepted,
        "a hard-rule item needs the human's own assertion (auth_ref)"
    );
    must(decide(
        &mut s,
        1,
        json!({"attested": false, "auth_ref": hex64('d')}),
        NOW + 5,
    ));
    // a normal item may be decided by attestation
    let mut s = to_awaiting_decision(1);
    must(decide(&mut s, 1, json!({"attested": true}), NOW + 5));
    // a change needs an approval reference; a non-change decision does not; reject/defer carry no change
    let mut s = to_awaiting_decision(1);
    assert_eq!(
        expect_err(decide(&mut s, 1, json!({"approval_ref": null}), NOW + 5)),
        CouncilError::MissingApproval
    );
    assert!(
        matches!(
            expect_err(decide(
                &mut s,
                1,
                json!({"decision":"reject","reason":"out_of_scope"}),
                NOW + 5
            )),
            CouncilError::Invalid(_)
        ),
        "a rejected item carries no change"
    );
    assert!(
        matches!(
            expect_err(decide(
                &mut s,
                1,
                json!({"decision":"defer","reason":"wait_for_data"}),
                NOW + 5
            )),
            CouncilError::Invalid(_)
        ),
        "a deferred item carries no change"
    );
    must(decide(
        &mut s,
        1,
        json!({"change_kind":"none","approval_ref":null}),
        NOW + 5,
    ));
}

#[test]
fn s11_nothing_changes_without_a_recorded_human_decision() {
    let mut s = to_awaiting_decision(3);
    assert!(
        s.approved_changes().is_empty(),
        "a complete packet changes nothing"
    );
    assert_eq!(s.pending_items(), vec!["f-1", "f-2", "f-3"]);
    must(decide(
        &mut s,
        2,
        json!({"approval_ref": "appr-2"}),
        NOW + 5,
    ));
    must(decide(
        &mut s,
        3,
        json!({"decision":"defer","reason":"wait_for_data","change_kind":"none","approval_ref":null}),
        NOW + 6,
    ));
    assert_eq!(s.pending_items(), vec!["f-1"]);
    assert_eq!(
        s.approved_changes(),
        vec![ApprovedChange {
            finding_id: "f-2".into(),
            change_kind: "test".into(),
            approval_ref: "appr-2".into()
        }],
        "only the accepted item with its approval"
    );
}

#[test]
fn s12_an_absent_human_means_pending_and_no_change() {
    let mut s = to_awaiting_decision(2);
    must(decide(
        &mut s,
        1,
        json!({"approval_ref": "appr-1"}),
        NOW + 500,
    ));
    assert_eq!(s.state(EXPIRES - 1), SessionState::AwaitingDecision);
    assert_eq!(s.state(EXPIRES), SessionState::Expired);
    assert_eq!(
        s.pending_items(),
        vec!["f-2"],
        "the undecided item stays pending"
    );
    assert_eq!(
        expect_err(decide(
            &mut s,
            2,
            json!({"approval_ref": "appr-2"}),
            EXPIRES
        )),
        CouncilError::Expired,
        "no decision after the expiry"
    );
    assert_eq!(
        expect_err(s.apply(&finding(5), Role::Critic, EXPIRES + 1)),
        CouncilError::Expired
    );
    assert_eq!(
        s.approved_changes().len(),
        1,
        "the decision recorded before the expiry stands; nothing else changed"
    );
    // closing as expired is only possible at or after the expiry, with true counts
    let bad_early = ev(
        "session.expired",
        json!({"closing":"expired_pending","accepted":1,"rejected":0,"deferred":0,"pending":1}),
    );
    assert_eq!(
        expect_err(s.apply(&bad_early, Role::Scheduler, EXPIRES - 1)),
        CouncilError::OutOfOrder
    );
    let wrong_counts = ev(
        "session.expired",
        json!({"closing":"expired_pending","accepted":2,"rejected":0,"deferred":0,"pending":0}),
    );
    assert_eq!(
        expect_err(s.apply(&wrong_counts, Role::Scheduler, EXPIRES)),
        CouncilError::Incomplete
    );
    must(s.apply(&bad_early, Role::Scheduler, EXPIRES));
    assert_eq!(s.state(EXPIRES + 1), SessionState::Expired);
}

#[test]
fn s13_no_quorum_means_no_change_and_closes_as_no_quorum() {
    // The critic never reports (provider down): no silent substitution, the session just expires.
    let mut s = open_session();
    assert!(!s.quorum().valid());
    assert!(s.approved_changes().is_empty());
    assert_eq!(s.state(EXPIRES), SessionState::Expired);
    let close = ev(
        "session.expired",
        json!({"closing":"no_quorum","accepted":0,"rejected":0,"deferred":0,"pending":0}),
    );
    assert_eq!(
        expect_err(s.apply(&close, Role::Scheduler, EXPIRES - 1)),
        CouncilError::OutOfOrder
    );
    must(s.apply(&close, Role::Scheduler, EXPIRES));
    // "no_quorum" is refused when the quorum is in fact complete
    let mut full = to_awaiting_decision(1);
    let lie = ev(
        "session.expired",
        json!({"closing":"no_quorum","accepted":0,"rejected":0,"deferred":0,"pending":1}),
    );
    assert_eq!(
        expect_err(full.apply(&lie, Role::Scheduler, EXPIRES)),
        CouncilError::Incomplete
    );
}

#[test]
fn s14_closing_early_or_with_false_counts_is_refused_and_a_closed_session_takes_nothing() {
    let mut s = to_awaiting_decision(2);
    must(decide(
        &mut s,
        1,
        json!({"approval_ref": "appr-1"}),
        NOW + 5,
    ));
    let close = |a, r, d, p| {
        ev(
            "session.closed",
            json!({"closing":"all_decided","accepted":a,"rejected":r,"deferred":d,"pending":p}),
        )
    };
    assert_eq!(
        expect_err(s.apply(&close(1, 0, 0, 1), Role::Scheduler, NOW + 6)),
        CouncilError::Incomplete,
        "all_decided while an item is pending"
    );
    must(decide(
        &mut s,
        2,
        json!({"decision":"defer","reason":"wait_for_data","change_kind":"none","approval_ref":null}),
        NOW + 7,
    ));
    assert_eq!(
        expect_err(s.apply(&close(2, 0, 0, 0), Role::Scheduler, NOW + 8)),
        CouncilError::Incomplete,
        "counts that do not match the decisions"
    );
    must(s.apply(&close(1, 0, 1, 0), Role::Scheduler, NOW + 8));
    assert_eq!(
        expect_err(finding_after_close(&mut s)),
        CouncilError::OutOfOrder
    );
    assert_eq!(
        expect_err(decide(&mut s, 1, json!({}), NOW + 9)),
        CouncilError::OutOfOrder
    );
}

fn finding_after_close(s: &mut Session) -> Result<(), CouncilError> {
    s.apply(&finding(7), Role::Critic, NOW + 9)
}

#[test]
fn s15_the_window_and_findings_hashes_match_an_independent_implementation() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/council_v1.json")).unwrap();
    let refs: Vec<String> = v["window"]["refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert_eq!(window_hash(&refs), v["window"]["hash"].as_str().unwrap());
    let mut rev = refs.clone();
    rev.reverse();
    assert_eq!(
        window_hash(&rev),
        v["window"]["hash"].as_str().unwrap(),
        "order of the input does not matter"
    );
    let ids: Vec<String> = v["findings"]["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert_eq!(findings_hash(&ids), v["findings"]["hash"].as_str().unwrap());
    assert_ne!(
        window_hash(&ids),
        findings_hash(&ids),
        "the two hashes are domain separated"
    );
    assert_ne!(
        findings_hash(&["f-1".to_string()]),
        findings_hash(&["f-1".to_string(), "f-2".to_string()])
    );
}
