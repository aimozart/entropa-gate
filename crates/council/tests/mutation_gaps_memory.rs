//! Boundary tests added in S12d-c after the first mutation run on memory.rs and memory_eval.rs (docs/evidence/s12d-c-mutants.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::json;

fn t(terms: &[&str]) -> Vec<String> {
    terms.iter().map(|s| s.to_string()).collect()
}

#[test]
fn z1_exactly_sixteen_terms_are_accepted() {
    let sixteen: Vec<String> = (0..16).map(|i| format!("class=c{i}")).collect();
    let p = Precedent {
        id: "a".into(),
        tenant: "t1".into(),
        terms: sixteen.clone(),
    };
    let idx = must(LexicalIndex::build(LexicalConfig::default(), vec![p], &[]));
    assert_eq!(must(idx.search("t1", &sixteen, 1))[0].score, 1000);
}

#[test]
fn z2_one_wrong_event_type_is_enough_to_refuse() {
    let finding = ev("finding.submitted", json!({}));
    let decision = ev("decision.recorded", json!({}));
    must(precedent_terms(&finding, &decision));
    for (a, b) in [(&finding, &finding), (&decision, &decision)] {
        assert!(matches!(
            expect_err(precedent_terms(a, b)),
            CouncilError::Invalid(_)
        ));
    }
}

#[test]
fn z3_a_field_weight_needs_a_valid_name_and_a_nonzero_weight() {
    let p = || {
        vec![Precedent {
            id: "a".into(),
            tenant: "t1".into(),
            terms: t(&["class=c1"]),
        }]
    };
    for (name, weights) in [
        ("zero weight", vec![("class".to_string(), 0)]),
        ("bad field name", vec![("Class X".to_string(), 3)]),
    ] {
        let c = LexicalConfig {
            weights,
            threshold: 0,
        };
        assert!(
            matches!(
                LexicalIndex::build(c, p(), &[]),
                Err(CouncilError::Invalid(_))
            ),
            "{name}"
        );
    }
}

#[test]
fn z4_thresholds_are_inclusive() {
    let r = |recall, abst, v| RetrievalReport {
        recall_permille: Some(recall),
        mrr_permille: Some(0),
        abstention_permille: Some(abst),
        violations: v,
    };
    let t = RetrievalThresholds::default();
    assert_eq!(r(900, 950, 0).meets(&t), Ok(()), "exactly at the limits");
    assert_eq!(r(899, 950, 0).meets(&t), Err(vec!["recall".to_string()]));
    assert_eq!(
        r(900, 949, 0).meets(&t),
        Err(vec!["abstention".to_string()])
    );
    assert_eq!(
        r(900, 950, 1).meets(&t),
        Err(vec!["violations".to_string()])
    );
}

#[test]
fn z5_a_near_case_differs_from_its_precedent_in_exactly_the_reason() {
    let s = must(planted_retrieval_suite(1, 200));
    let mut checked = 0;
    for c in s.cases.iter().filter(|c| c.id.starts_with("near-")) {
        let p = s
            .precedents
            .iter()
            .find(|p| p.id == c.expected.as_ref().unwrap()[0])
            .unwrap();
        let diff: Vec<&String> = c.query.iter().filter(|q| !p.terms.contains(q)).collect();
        assert_eq!(diff.len(), 1, "{}", c.id);
        let reason = diff[0]
            .strip_prefix("reason=reason_")
            .expect("the reason differs");
        assert!(reason.parse::<usize>().unwrap() < 6, "{}", c.id);
        checked += 1;
    }
    assert_eq!(checked, 10);
}
