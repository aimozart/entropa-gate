//! Decision memory (the decision-memory design notes sections 3, 4, 7, 8): the lexical index, its hashes, the retrieval
//! evaluation harness and the planted-suite generator. Golden values come from docs/evidence/s12d-b-gen-vectors.py.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("vectors/memory_v1.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

fn t(terms: &[&str]) -> Vec<String> {
    terms.iter().map(|s| s.to_string()).collect()
}

fn prec(id: &str, tenant: &str, terms: &[&str]) -> Precedent {
    Precedent {
        id: id.into(),
        tenant: tenant.into(),
        terms: t(terms),
    }
}

fn vector_precedents() -> Vec<Precedent> {
    vectors()["precedents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| Precedent {
            id: p["id"].as_str().unwrap().into(),
            tenant: p["tenant"].as_str().unwrap().into(),
            terms: strings(&p["terms"]),
        })
        .collect()
}

fn vector_config(threshold: u32) -> LexicalConfig {
    let v = vectors();
    let weights = v["weights"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, w)| (k.clone(), w.as_u64().unwrap() as u32))
        .collect();
    LexicalConfig { weights, threshold }
}

fn revoked() -> Vec<String> {
    strings(&vectors()["revoked"])
}

fn vector_index(threshold: u32) -> LexicalIndex {
    must(LexicalIndex::build(
        vector_config(threshold),
        vector_precedents(),
        &revoked(),
    ))
}

fn weights_map(c: &LexicalConfig) -> BTreeMap<String, u32> {
    c.weights.iter().cloned().collect()
}

#[test]
fn x1_the_default_scorer_is_the_documented_one() {
    let d = LexicalConfig::default();
    assert_eq!(d.threshold, 400);
    assert_eq!(weights_map(&d), weights_map(&vector_config(400)));
    assert_eq!(weights_map(&d).len(), 5);
}

#[test]
fn x2_the_index_and_manifest_hashes_match_an_independent_implementation() {
    let v = vectors();
    let idx = vector_index(400);
    assert_eq!(idx.len(), 3, "p9 is revoked");
    assert!(!idx.is_empty());
    assert_eq!(idx.index_hash(), v["index_hash"].as_str().unwrap());
    assert_eq!(idx.manifest_hash(), v["manifest_hash"].as_str().unwrap());
    assert_eq!(
        manifest_hash(&t(&["p1", "p2", "p3"]), &revoked()),
        v["manifest_hash"].as_str().unwrap()
    );
    assert_eq!(
        vector_index(0).index_hash(),
        v["index_hash_other_threshold_0"].as_str().unwrap(),
        "the threshold is part of the scorer descriptor"
    );
}

#[test]
fn x3_retrieval_matches_the_independent_scorer() {
    for q in vectors()["queries"].as_array().unwrap() {
        let idx = vector_index(q["threshold"].as_u64().unwrap() as u32);
        let got = must(idx.search(
            q["tenant"].as_str().unwrap(),
            &strings(&q["query"]),
            q["k"].as_u64().unwrap() as usize,
        ));
        let want: Vec<(String, u64)> = q["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                (
                    h["id"].as_str().unwrap().into(),
                    h["score"].as_u64().unwrap(),
                )
            })
            .collect();
        let got: Vec<(String, u64)> = got
            .into_iter()
            .map(|h| (h.id, u64::from(h.score)))
            .collect();
        assert_eq!(got, want, "{q}");
    }
}

#[test]
fn x4_the_hash_ignores_input_order_and_changes_with_everything_that_matters() {
    let base = vector_index(400).index_hash();
    let mut rev = vector_precedents();
    rev.reverse();
    for p in &mut rev {
        p.terms.reverse();
    }
    assert_eq!(
        must(LexicalIndex::build(vector_config(400), rev, &revoked())).index_hash(),
        base,
        "order of precedents and of terms"
    );
    let h = |ps: Vec<Precedent>, c: LexicalConfig| {
        must(LexicalIndex::build(c, ps, &revoked())).index_hash()
    };
    let mut weights = vector_config(400);
    weights.weights.retain(|(k, _)| k != "reason");
    weights.weights.push(("reason".into(), 2));
    assert_ne!(h(vector_precedents(), weights), base, "a field weight");
    let mut changed = vector_precedents();
    changed[0].terms[0] = "change=lesson".into();
    assert_ne!(h(changed, vector_config(400)), base, "a term");
    let mut renamed = vector_precedents();
    renamed[1].id = "p8".into();
    assert_ne!(h(renamed, vector_config(400)), base, "an id");
    let mut moved = vector_precedents();
    moved[0].tenant = "hippagrchealthcare".into();
    assert_ne!(h(moved, vector_config(400)), base, "a tenant");
    let mut fewer = vector_precedents();
    fewer.remove(1);
    assert_ne!(h(fewer, vector_config(400)), base, "a missing precedent");
    let mut more = vector_precedents();
    more.push(prec(
        "p4",
        "entropa",
        &["class=policy_gap", "decision=accept"],
    ));
    assert_ne!(h(more, vector_config(400)), base, "an added precedent");
}

#[test]
fn x5_a_revoked_precedent_is_left_out_of_the_index_but_stays_in_the_manifest() {
    let with_revoked = vector_index(400);
    let without: Vec<Precedent> = vector_precedents()
        .into_iter()
        .filter(|p| p.id != "p9")
        .collect();
    let plain = must(LexicalIndex::build(vector_config(400), without, &[]));
    assert_eq!(
        with_revoked.index_hash(),
        plain.index_hash(),
        "the index is the same"
    );
    assert_ne!(
        with_revoked.manifest_hash(),
        plain.manifest_hash(),
        "the manifest records the revocation"
    );
    let q = t(&[
        "class=wrong_subject",
        "decision=accept",
        "severity=high",
        "change=test",
        "reason=evidence_sufficient",
    ]);
    let hits = must(with_revoked.search("entropa", &q, 5));
    assert!(
        hits.iter().all(|h| h.id != "p9"),
        "a revoked precedent is never returned: {hits:?}"
    );
}

#[test]
fn x6_building_refuses_bad_precedents() {
    let ok = |ps: Vec<Precedent>| LexicalIndex::build(LexicalConfig::default(), ps, &[]);
    let good = prec("a", "entropa", &["class=c1", "decision=accept"]);
    must(ok(vec![good.clone()]));
    let canary = entropa_synthetic::canary(5);
    let many: Vec<String> = (0..17).map(|i| format!("class=c{i}")).collect();
    let bad: Vec<(&str, Vec<Precedent>)> = vec![
        ("no precedent", vec![]),
        ("duplicate id", vec![good.clone(), good.clone()]),
        ("empty id", vec![prec("", "entropa", &["class=c1"])]),
        (
            "id with a space",
            vec![prec("a b", "entropa", &["class=c1"])],
        ),
        (
            "id of 65 characters",
            vec![prec(&"a".repeat(65), "entropa", &["class=c1"])],
        ),
        ("canary id", vec![prec(&canary, "entropa", &["class=c1"])]),
        ("empty tenant", vec![prec("a", "", &["class=c1"])]),
        (
            "tenant with a space",
            vec![prec("a", "en tropa", &["class=c1"])],
        ),
        ("canary tenant", vec![prec("a", &canary, &["class=c1"])]),
        ("no term", vec![prec("a", "entropa", &[])]),
        ("term without =", vec![prec("a", "entropa", &["classc1"])]),
        (
            "term with an empty value",
            vec![prec("a", "entropa", &["class="])],
        ),
        (
            "term with an empty field",
            vec![prec("a", "entropa", &["=c1"])],
        ),
        (
            "term with upper case",
            vec![prec("a", "entropa", &["Class=c1"])],
        ),
        (
            "term with a space",
            vec![prec("a", "entropa", &["class=c 1"])],
        ),
        (
            "term with two =",
            vec![prec("a", "entropa", &["class=c=1"])],
        ),
        (
            "canary term",
            vec![prec(
                "a",
                "entropa",
                &[&format!("class={}", canary.to_lowercase())],
            )],
        ),
        (
            "repeated term",
            vec![prec("a", "entropa", &["class=c1", "class=c1"])],
        ),
        (
            "17 terms",
            vec![Precedent {
                id: "a".into(),
                tenant: "entropa".into(),
                terms: many,
            }],
        ),
    ];
    for (name, ps) in bad {
        assert!(matches!(ok(ps), Err(CouncilError::Invalid(_))), "{name}");
    }
    assert!(
        matches!(
            LexicalIndex::build(
                LexicalConfig::default(),
                vec![good.clone()],
                &["a".to_string()]
            ),
            Err(CouncilError::Invalid(_))
        ),
        "everything revoked leaves nothing"
    );
}

fn tie_index(config: LexicalConfig) -> LexicalIndex {
    must(LexicalIndex::build(
        config,
        vec![
            prec("a2", "t1", &["class=c1", "decision=accept"]),
            prec("a1", "t1", &["class=c1", "decision=accept"]),
            prec(
                "a3",
                "t1",
                &["class=c1", "decision=accept", "severity=high"],
            ),
            prec("b1", "t2", &["class=c1", "decision=accept"]),
        ],
        &[],
    ))
}

#[test]
fn x7_results_are_best_first_ties_go_to_the_lower_id_and_k_caps_the_list() {
    let idx = tie_index(LexicalConfig::default());
    let q = t(&["class=c1", "decision=accept"]);
    // a1 and a2 score 1000; a3: 1000 x 7 / 9 = 777
    let all = must(idx.search("t1", &q, 5));
    assert_eq!(
        all.iter()
            .map(|h| (h.id.as_str(), h.score))
            .collect::<Vec<_>>(),
        vec![("a1", 1000), ("a2", 1000), ("a3", 777)]
    );
    assert_eq!(must(idx.search("t1", &q, 2)).len(), 2);
    assert_eq!(must(idx.search("t1", &q, 1))[0].id, "a1");
}

#[test]
fn x8_a_tenant_reads_only_its_own_precedents_and_an_unknown_tenant_gets_nothing() {
    let idx = tie_index(LexicalConfig::default());
    let q = t(&["class=c1", "decision=accept"]);
    let t2 = must(idx.search("t2", &q, 5));
    assert_eq!(
        t2.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(),
        vec!["b1"]
    );
    assert_eq!(
        must(idx.search("nobody", &q, 5)),
        vec![],
        "row-level security: zero rows, not an error"
    );
    assert!(
        matches!(idx.search("no body", &q, 5), Err(CouncilError::Invalid(_))),
        "a malformed tenant is refused"
    );
}

#[test]
fn x9_below_the_threshold_nothing_is_returned_and_an_unlisted_field_weighs_one() {
    let idx = tie_index(LexicalConfig::default());
    // query {class=zzz 4, decision=accept 3}; a1 {class=c1 4, decision=accept 3}: intersection 3, union 4 + 3 + 4 = 11 -> 272;
    // a3 (with severity=high 2): 3 / 13 -> 230; all below 400
    assert!(
        must(idx.search("t1", &t(&["class=zzz", "decision=accept"]), 5)).is_empty(),
        "272 and 230 are below 400: abstain"
    );
    let loose = tie_index(LexicalConfig {
        weights: LexicalConfig::default().weights,
        threshold: 0,
    });
    let weak = must(loose.search("t1", &t(&["class=zzz", "decision=accept"]), 5));
    assert_eq!(weak.len(), 3, "with threshold 0 the weak matches come back");
    let custom = must(LexicalIndex::build(
        LexicalConfig {
            weights: vec![],
            threshold: 0,
        },
        vec![prec("w1", "t1", &["zzz=1", "class=c1"])],
        &[],
    ));
    // every field weighs 1: intersection 1, union 2 -> 500
    assert_eq!(must(custom.search("t1", &t(&["zzz=1"]), 3))[0].score, 500);
}

#[test]
fn x10_a_query_must_be_small_well_formed_and_free_of_canaries() {
    let idx = tie_index(LexicalConfig::default());
    let canary = entropa_synthetic::canary(6).to_lowercase();
    let many: Vec<String> = (0..17).map(|i| format!("class=c{i}")).collect();
    assert!(matches!(
        idx.search("t1", &t(&["class=c1"]), 0),
        Err(CouncilError::Limit(_))
    ));
    assert!(matches!(
        idx.search("t1", &t(&["class=c1"]), 6),
        Err(CouncilError::Limit(_))
    ));
    for (name, q) in [
        ("empty", vec![]),
        ("no =", t(&["classc1"])),
        ("upper case", t(&["Class=c1"])),
        ("a space", t(&["class=c 1"])),
        ("repeated", t(&["class=c1", "class=c1"])),
        ("a canary", vec![format!("class={canary}")]),
        ("17 terms", many),
    ] {
        assert!(
            matches!(idx.search("t1", &q, 3), Err(CouncilError::Invalid(_))),
            "{name}"
        );
    }
}

#[test]
fn x11_search_is_deterministic() {
    let idx = tie_index(LexicalConfig::default());
    let q = t(&["class=c1", "decision=accept", "severity=high"]);
    assert_eq!(must(idx.search("t1", &q, 5)), must(idx.search("t1", &q, 5)));
}

#[test]
fn x12_terms_of_a_precedent_come_from_the_finding_and_its_accepted_decision() {
    let finding = ev("finding.submitted", json!({}));
    let decision = ev(
        "decision.recorded",
        json!({"auth_ref": hex64('d'), "attested": true}),
    );
    assert_eq!(
        must(precedent_terms(&finding, &decision)),
        t(&[
            "change=test",
            "class=missing_approval",
            "decision=accept",
            "reason=evidence_sufficient",
            "severity=high"
        ]),
        "sorted; no attested, no reference, no hash"
    );
    let other = ev("decision.recorded", json!({"finding_id": "f-2"}));
    assert!(
        matches!(
            expect_err(precedent_terms(&finding, &other)),
            CouncilError::Invalid(_)
        ),
        "another finding's decision"
    );
    let rejected = ev(
        "decision.recorded",
        json!({"decision": "reject", "reason": "out_of_scope", "change_kind": "none", "approval_ref": null}),
    );
    assert!(
        matches!(
            expect_err(precedent_terms(&finding, &rejected)),
            CouncilError::Invalid(_)
        ),
        "only an accepted decision"
    );
    assert!(
        matches!(
            expect_err(precedent_terms(&decision, &finding)),
            CouncilError::Invalid(_)
        ),
        "swapped arguments"
    );
}

#[test]
fn x13_the_memory_hash_binds_a_decision_to_the_precedents_it_saw() {
    let v = vectors();
    let idx = v["index_hash"].as_str().unwrap();
    let want = v["memory"]["hash"].as_str().unwrap();
    assert_eq!(must(memory_hash(idx, &strings(&v["memory"]["ids"]))), want);
    assert_eq!(
        must(memory_hash(idx, &t(&["p1", "p2"]))),
        want,
        "order of the ids does not matter"
    );
    assert_ne!(must(memory_hash(idx, &t(&["p1"]))), want, "the ids");
    assert_ne!(
        must(memory_hash(&hex64('7'), &t(&["p2", "p1"]))),
        want,
        "the index"
    );
    assert!(matches!(
        expect_err(memory_hash(idx, &[])),
        CouncilError::Invalid(_)
    ));
    assert!(matches!(
        expect_err(memory_hash(idx, &t(&["a", "b", "c", "d", "e", "f"]))),
        CouncilError::Limit(_)
    ));
    assert!(matches!(
        expect_err(memory_hash(idx, &t(&["has space"]))),
        CouncilError::Invalid(_)
    ));
    assert!(matches!(
        expect_err(memory_hash(idx, &[entropa_synthetic::canary(4)])),
        CouncilError::Invalid(_)
    ));
    assert!(matches!(
        expect_err(memory_hash("not a hash", &t(&["p1"]))),
        CouncilError::Invalid(_)
    ));
    must(memory_hash(idx, &t(&["a", "b", "c", "d", "e"])));
}

// ---- the retrieval evaluation harness ---------------------------------------------------------------------------------

fn small_index() -> LexicalIndex {
    must(LexicalIndex::build(
        LexicalConfig::default(),
        vec![
            prec(
                "r1",
                "t1",
                &[
                    "change=test",
                    "class=c1",
                    "decision=accept",
                    "reason=r1",
                    "severity=high",
                ],
            ),
            prec(
                "r2",
                "t1",
                &[
                    "change=test",
                    "class=c2",
                    "decision=accept",
                    "reason=r1",
                    "severity=high",
                ],
            ),
            prec(
                "r3",
                "t1",
                &[
                    "change=lesson",
                    "class=c3",
                    "decision=accept",
                    "reason=r2",
                    "severity=low",
                ],
            ),
            prec(
                "x1",
                "t2",
                &[
                    "change=test",
                    "class=c1",
                    "decision=accept",
                    "reason=r1",
                    "severity=high",
                ],
            ),
        ],
        &[],
    ))
}

fn case(
    id: &str,
    tenant: &str,
    q: &[&str],
    expected: Option<&[&str]>,
    forbidden: &[&str],
) -> RetrievalCase {
    RetrievalCase {
        id: id.into(),
        tenant: tenant.into(),
        query: t(q),
        expected: expected.map(t),
        forbidden: t(forbidden),
    }
}

fn harness_cases() -> Vec<RetrievalCase> {
    let r1 = [
        "change=test",
        "class=c1",
        "decision=accept",
        "reason=r1",
        "severity=high",
    ];
    let r2 = [
        "change=test",
        "class=c2",
        "decision=accept",
        "reason=r1",
        "severity=high",
    ];
    vec![
        case("c1", "t1", &r1, Some(&["r1"]), &["x1"]), // r1 1000, r2 500: rank 1
        case("c2", "t1", &r2, Some(&["r2"]), &["x1"]), // rank 1
        case(
            "c3",
            "t1",
            &[
                "change=test",
                "decision=accept",
                "reason=r1",
                "severity=high",
            ],
            Some(&["r2"]),
            &[],
        ), // r1 and r2 tie at 666: rank 2
        case(
            "c4",
            "t1",
            &["class=zzz", "decision=accept"],
            Some(&[]),
            &[],
        ), // 187: abstain
        case("c5", "t2", &r1, None, &["r1", "r2"]),    // only x1 in tenant t2
    ]
}

#[test]
fn x14_the_harness_computes_recall_mrr_abstention_and_violations() {
    let r = must(evaluate_retrieval(&small_index(), &harness_cases(), 3));
    assert_eq!(r.recall_permille, Some(1000), "c1, c2, c3 are found");
    assert_eq!(
        r.mrr_permille,
        Some(833),
        "ranks 1, 1, 2: (1000 + 1000 + 500) / 3 = 833"
    );
    assert_eq!(r.abstention_permille, Some(1000), "c4 returned nothing");
    assert_eq!(r.violations, 0);
    assert_eq!(r.meets(&RetrievalThresholds::default()), Ok(()));
}

#[test]
fn x15_a_miss_a_noisy_abstention_and_a_forbidden_hit_are_all_counted() {
    let mut cases = harness_cases();
    cases.push(case(
        "c6",
        "t1",
        &[
            "change=test",
            "class=c1",
            "decision=accept",
            "reason=r1",
            "severity=high",
        ],
        Some(&["r3"]),
        &["r2"],
    ));
    cases.push(case(
        "c7",
        "t1",
        &[
            "change=test",
            "class=c1",
            "decision=accept",
            "reason=r1",
            "severity=high",
        ],
        Some(&[]),
        &[],
    ));
    let r = must(evaluate_retrieval(&small_index(), &cases, 3));
    assert_eq!(
        r.recall_permille,
        Some(750),
        "3 of 4 expected hits found (c6 expects r3, which is not returned)"
    );
    assert_eq!(r.mrr_permille, Some(625), "(1000 + 1000 + 500 + 0) / 4");
    assert_eq!(r.abstention_permille, Some(500), "c4 abstained, c7 did not");
    assert_eq!(r.violations, 1, "c6 returned the forbidden r2");
    let failed = r.meets(&RetrievalThresholds::default()).unwrap_err();
    for name in ["recall", "abstention", "violations"] {
        assert!(failed.iter().any(|f| f == name), "{failed:?}");
    }
}

#[test]
fn x16_k_limits_the_recall_window_and_a_metric_that_was_not_measured_fails() {
    let c3 = [case(
        "c3",
        "t1",
        &[
            "change=test",
            "decision=accept",
            "reason=r1",
            "severity=high",
        ],
        Some(&["r2"]),
        &[],
    )];
    assert_eq!(
        must(evaluate_retrieval(&small_index(), &c3, 2)).recall_permille,
        Some(1000),
        "rank 2 is inside k = 2"
    );
    assert_eq!(
        must(evaluate_retrieval(&small_index(), &c3, 1)).recall_permille,
        Some(0),
        "rank 2 is outside k = 1"
    );
    let none = [case("c5", "t2", &["class=c1"], None, &["r1"])];
    let r = must(evaluate_retrieval(&small_index(), &none, 3));
    assert_eq!(
        (r.recall_permille, r.mrr_permille, r.abstention_permille),
        (None, None, None)
    );
    let failed = r.meets(&RetrievalThresholds::default()).unwrap_err();
    assert!(
        failed.iter().any(|f| f == "recall") && failed.iter().any(|f| f == "abstention"),
        "{failed:?}"
    );
    assert!(matches!(
        expect_err(evaluate_retrieval(&small_index(), &c3, 0)),
        CouncilError::Limit(_)
    ));
}

#[test]
fn x17_the_default_acceptance_thresholds() {
    let d = RetrievalThresholds::default();
    assert_eq!(
        (d.recall_min, d.abstention_min, d.violations_max),
        (900, 950, 0)
    );
}

// ---- the planted-suite generator and the quality gate ------------------------------------------------------------------

#[test]
fn x18_the_planted_suite_is_deterministic_and_well_formed() {
    let a = must(planted_retrieval_suite(1, 200));
    assert_eq!(a, must(planted_retrieval_suite(1, 200)));
    assert_ne!(a, must(planted_retrieval_suite(2, 200)));
    assert_eq!(a.revoked.len(), 10, "n / 20 revoked precedents");
    assert_eq!(a.precedents.len(), 210);
    let ids: std::collections::BTreeSet<&str> =
        a.precedents.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids.len(), 210, "ids are unique");
    assert!(a.revoked.iter().all(|r| ids.contains(r.as_str())));
    for p in &a.precedents {
        assert!(
            ["entropa", "bigironbank", "hippagrchealthcare"].contains(&p.tenant.as_str()),
            "{}",
            p.tenant
        );
    }
    must(LexicalIndex::build(
        LexicalConfig::default(),
        a.precedents.clone(),
        &a.revoked,
    ));
    for kind in ["exact-", "near-", "none-", "poison-", "xtenant-"] {
        assert!(
            a.cases.iter().filter(|c| c.id.starts_with(kind)).count() >= 5,
            "{kind}"
        );
    }
    for c in &a.cases {
        for e in c.expected.iter().flatten() {
            let p = a
                .precedents
                .iter()
                .find(|p| &p.id == e)
                .unwrap_or_else(|| panic!("{e} is not a precedent"));
            assert_eq!(
                p.tenant, c.tenant,
                "{}: the expected precedent belongs to the asking tenant",
                c.id
            );
            assert!(
                !a.revoked.contains(e),
                "{}: an expected precedent is never revoked",
                c.id
            );
        }
        if c.id.starts_with("poison-") {
            assert!(
                !c.forbidden.is_empty() && c.forbidden.iter().all(|f| a.revoked.contains(f)),
                "{}",
                c.id
            );
        }
        if c.id.starts_with("xtenant-") {
            assert!(!c.forbidden.is_empty(), "{}", c.id);
            for f in &c.forbidden {
                assert_ne!(
                    a.precedents.iter().find(|p| &p.id == f).unwrap().tenant,
                    c.tenant,
                    "{}",
                    c.id
                );
            }
        }
    }
}

#[test]
fn x19_the_lexical_index_passes_the_planted_gate_for_several_seeds() {
    for seed in 1..=3u64 {
        let s = must(planted_retrieval_suite(seed, 200));
        let idx = must(LexicalIndex::build(
            LexicalConfig::default(),
            s.precedents.clone(),
            &s.revoked,
        ));
        let r = must(evaluate_retrieval(&idx, &s.cases, 3));
        assert_eq!(
            r.violations, 0,
            "seed {seed}: poisoned and cross-tenant entries never surface"
        );
        assert_eq!(
            r.meets(&RetrievalThresholds::default()),
            Ok(()),
            "seed {seed}: {r:?}"
        );
    }
}

#[test]
fn x20_an_index_that_forgot_the_revocations_is_caught_by_the_gate() {
    let s = must(planted_retrieval_suite(1, 200));
    let leaky = must(LexicalIndex::build(
        LexicalConfig::default(),
        s.precedents.clone(),
        &[],
    ));
    let r = must(evaluate_retrieval(&leaky, &s.cases, 3));
    assert!(
        r.violations > 0,
        "revoked precedents surface when the revocation list is ignored"
    );
    assert!(r
        .meets(&RetrievalThresholds::default())
        .unwrap_err()
        .iter()
        .any(|f| f == "violations"));
}
