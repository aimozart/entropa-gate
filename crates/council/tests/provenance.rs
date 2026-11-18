//! Decision memory: pinned, hashed, exact retrieval; provenance records; admission of signed accepted entries only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("vectors/council_v1.json");

type Entries = Vec<(String, Vec<f32>)>;

fn model() -> ModelDescriptor {
    ModelDescriptor {
        id: "test-embed".into(),
        dim: 3,
        normalization: "unit".into(),
    }
}
fn entries() -> Vec<(String, Vec<f32>)> {
    vec![
        ("p2".into(), vec![0.0, 1.0, 0.0]),
        ("p1".into(), vec![1.0, 0.0, 0.0]),
        ("p3".into(), vec![0.5, 0.5, 0.0]),
    ]
}
fn index() -> Index {
    must(Index::build(model(), entries()))
}

#[test]
fn v1_the_index_hash_matches_an_independent_implementation() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(index().index_hash(), v["index"]["hash"].as_str().unwrap());
}

#[test]
fn v2_the_hash_does_not_depend_on_insertion_order_but_on_everything_else() {
    let base = index().index_hash();
    let mut rev = entries();
    rev.reverse();
    assert_eq!(must(Index::build(model(), rev)).index_hash(), base);
    let h = |m: ModelDescriptor, e: Vec<(String, Vec<f32>)>| must(Index::build(m, e)).index_hash();
    assert_ne!(
        h(
            ModelDescriptor {
                id: "other-embed".into(),
                ..model()
            },
            entries()
        ),
        base,
        "model id"
    );
    assert_ne!(
        h(
            ModelDescriptor {
                normalization: "none".into(),
                ..model()
            },
            entries()
        ),
        base,
        "normalisation"
    );
    let mut tweak = entries();
    tweak[0].1[1] = f32::from_bits(1.0f32.to_bits() + 1);
    assert_ne!(h(model(), tweak), base, "one ulp in one component");
    let mut renamed = entries();
    renamed[0].0 = "p9".into();
    assert_ne!(h(model(), renamed), base, "an id");
    let mut fewer = entries();
    fewer.pop();
    assert_ne!(h(model(), fewer), base, "an entry removed");
}

#[test]
fn v3_building_refuses_bad_indexes() {
    let bad: Vec<(&str, ModelDescriptor, Entries)> = vec![
        (
            "dimension mismatch",
            model(),
            vec![("a".into(), vec![1.0, 0.0])],
        ),
        (
            "duplicate id",
            model(),
            vec![
                ("a".into(), vec![1.0, 0.0, 0.0]),
                ("a".into(), vec![0.0, 1.0, 0.0]),
            ],
        ),
        ("empty id", model(), vec![("".into(), vec![1.0, 0.0, 0.0])]),
        (
            "id with a space",
            model(),
            vec![("a b".into(), vec![1.0, 0.0, 0.0])],
        ),
        (
            "id of 65 characters",
            model(),
            vec![("a".repeat(65), vec![1.0, 0.0, 0.0])],
        ),
        (
            "a canary as id",
            model(),
            vec![(entropa_synthetic::canary(1), vec![1.0, 0.0, 0.0])],
        ),
        ("NaN", model(), vec![("a".into(), vec![f32::NAN, 0.0, 0.0])]),
        (
            "infinity",
            model(),
            vec![("a".into(), vec![f32::INFINITY, 0.0, 0.0])],
        ),
        (
            "model dimension 0",
            ModelDescriptor { dim: 0, ..model() },
            vec![("a".into(), vec![])],
        ),
        ("no entries", model(), vec![]),
    ];
    for (name, m, e) in bad {
        assert!(
            matches!(Index::build(m, e), Err(CouncilError::Invalid(_))),
            "{name}"
        );
    }
}

#[test]
fn v4_exact_cosine_search_with_ties_broken_by_id() {
    let i = index();
    let r = must(i.search(&[1.0, 0.0, 0.0], 3));
    let got: Vec<(&str, f64)> = r.iter().map(|h| (h.id.as_str(), h.score)).collect();
    assert_eq!(
        got.iter().map(|g| g.0).collect::<Vec<_>>(),
        vec!["p1", "p3", "p2"]
    );
    assert!(
        (got[0].1 - 1.0).abs() < 1e-12
            && (got[1].1 - std::f64::consts::FRAC_1_SQRT_2).abs() < 1e-12
            && got[2].1.abs() < 1e-12,
        "{got:?}"
    );
    let t = must(i.search(&[1.0, 1.0, 0.0], 2));
    assert_eq!(
        t.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(),
        vec!["p3", "p1"],
        "p1 and p2 tie at 0.7071: the lower id wins"
    );
    assert_eq!(must(i.search(&[1.0, 0.0, 0.0], 1)).len(), 1);
}

#[test]
fn v5_search_is_reproducible_bit_for_bit() {
    let (a, b) = (index(), index());
    let q = [0.3, 0.9, 0.1];
    let (ra, rb) = (must(a.search(&q, 3)), must(b.search(&q, 3)));
    assert_eq!(ra.len(), rb.len());
    for (x, y) in ra.iter().zip(&rb) {
        assert_eq!(x.id, y.id);
        assert_eq!(x.score.to_bits(), y.score.to_bits());
    }
}

#[test]
fn v6_search_refuses_bad_queries_and_oversize_k() {
    let i = index();
    assert!(matches!(
        expect_err(i.search(&[1.0, 0.0, 0.0], 0)),
        CouncilError::Limit(_)
    ));
    assert!(matches!(
        expect_err(i.search(&[1.0, 0.0, 0.0], 6)),
        CouncilError::Limit(_)
    ));
    assert!(
        matches!(
            expect_err(i.search(&[1.0, 0.0], 1)),
            CouncilError::Invalid(_)
        ),
        "wrong dimension"
    );
    assert!(
        matches!(
            expect_err(i.search(&[0.0, 0.0, 0.0], 1)),
            CouncilError::Invalid(_)
        ),
        "zero vector"
    );
    assert!(matches!(
        expect_err(i.search(&[f32::NAN, 0.0, 0.0], 1)),
        CouncilError::Invalid(_)
    ));
}

#[test]
fn v7_a_provenance_record_names_exactly_the_ids_retrieved_and_the_index_used() {
    let i = index();
    let hits = must(i.search(&[1.0, 0.0, 0.0], 2));
    let p = must(precedent_reference(
        &i,
        "idx:1",
        &hits,
        "yes",
        "0123456789abcdef",
        NOW,
    ));
    let v: Value = serde_json::from_str(&p).unwrap();
    assert_eq!(v["type"], "precedent.referenced");
    assert_eq!(v["precedent_ids"], json!(["p1", "p3"]));
    assert_eq!(v["k"], 2);
    assert_eq!(v["index_hash"], i.index_hash());
    let mut signed = v.clone();
    signed["sig"] = json!("abcdef0123456789");
    must(decode_event(&signed.to_string()));
    // refusals
    let foreign = vec![Hit {
        id: "not-in-index".into(),
        score: 1.0,
    }];
    assert!(matches!(
        expect_err(precedent_reference(
            &i,
            "idx:1",
            &foreign,
            "yes",
            "0123456789abcdef",
            NOW
        )),
        CouncilError::Invalid(_)
    ));
    let six: Vec<Hit> = (0..6)
        .map(|n| Hit {
            id: format!("p{}", 1 + n % 3),
            score: 1.0,
        })
        .collect();
    assert!(matches!(
        expect_err(precedent_reference(
            &i,
            "idx:1",
            &six,
            "yes",
            "0123456789abcdef",
            NOW
        )),
        CouncilError::Limit(_)
    ));
    assert!(matches!(
        expect_err(precedent_reference(
            &i,
            "idx:1",
            &hits,
            "sort_of",
            "0123456789abcdef",
            NOW
        )),
        CouncilError::Invalid(_)
    ));
    assert!(
        matches!(
            expect_err(precedent_reference(
                &i,
                "idx:1",
                &[],
                "yes",
                "0123456789abcdef",
                NOW
            )),
            CouncilError::Invalid(_)
        ),
        "a retrieval that returned nothing records no reference"
    );
    assert!(matches!(
        expect_err(precedent_reference(
            &i,
            &entropa_synthetic::canary(3),
            &hits,
            "yes",
            "0123456789abcdef",
            NOW
        )),
        CouncilError::Invalid(_)
    ));
}

#[test]
fn v8_only_signed_accepted_decisions_enter_the_corpus() {
    let d = ev("decision.recorded", json!({}));
    let e = must(admit(&d, true, true));
    assert!(
        e.id.contains("f-1")
            && e.id.len() <= 64
            && e.id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".:_-".contains(c)),
        "{}",
        e.id
    );
    assert!(
        matches!(expect_err(admit(&d, false, true)), CouncilError::Invalid(_)),
        "not accepted by the human"
    );
    assert!(
        matches!(expect_err(admit(&d, true, false)), CouncilError::Verify(_)),
        "signature did not verify"
    );
    let rejected = ev(
        "decision.recorded",
        json!({"decision":"reject","reason":"out_of_scope","change_kind":"none","approval_ref":null}),
    );
    assert!(
        matches!(
            expect_err(admit(&rejected, true, true)),
            CouncilError::Invalid(_)
        ),
        "a rejected finding is not a precedent"
    );
    let deferred = ev(
        "decision.recorded",
        json!({"decision":"defer","reason":"wait_for_data","change_kind":"none","approval_ref":null}),
    );
    assert!(matches!(
        expect_err(admit(&deferred, true, true)),
        CouncilError::Invalid(_)
    ));
    assert!(
        matches!(
            expect_err(admit(&ev("finding.submitted", json!({})), true, true)),
            CouncilError::Invalid(_)
        ),
        "only decisions"
    );
}

#[test]
fn v9_the_rendering_of_an_entry_is_closed_code_text_only_and_deterministic() {
    let d = ev("decision.recorded", json!({"auth_ref": hex64('d')}));
    let a = must(admit(&d, true, true));
    let b = must(admit(&d, true, true));
    assert_eq!(a.rendering(), b.rendering());
    assert!(
        a.rendering()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " _.:/=,-\n".contains(c)),
        "{:?}",
        a.rendering()
    );
    assert!(
        a.rendering().contains("decision=accept")
            && a.rendering().contains("reason=evidence_sufficient")
    );
    assert!(
        !a.rendering().contains(&hex64('d')),
        "the auth reference is not part of the embedded text"
    );
    assert!(entropa_synthetic::scan(a.rendering()).is_empty());
}
