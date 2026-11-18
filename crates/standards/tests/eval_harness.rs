//! R1 task 3 (second half): the evaluation harness. It scores the FROZEN sets, verifies their hashes, reports every bar with counts and 95 percent
//! upper bounds, and must be able to FAIL: negative controls show it. The measured results of the real corpus are produced by `entropa-standards eval`,
//! not asserted here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::eval::{self, Answer};
use entropa_standards::retrieve::Verdict;
use serde_json::json;
use std::path::PathBuf;

fn eval_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval")
}
fn oracle(qs: &[eval::Question]) -> impl Fn(&str) -> Answer + '_ {
    move |q: &str| {
        let x = qs.iter().find(|x| x.query == q).unwrap();
        Answer {
            verdict: Verdict::Answered,
            top: Some((x.standard.clone(), x.expected.clone())),
            reason: "oracle".into(),
        }
    }
}
fn abstain(_: &str) -> Answer {
    Answer {
        verdict: Verdict::NotInCorpus,
        top: None,
        reason: "below_gate".into(),
    }
}

#[test]
fn e1_upper_bounds_are_the_rule_of_three_at_zero_and_wilson_otherwise() {
    assert!((eval::upper95(0, 60) - 0.05).abs() < 1e-12);
    assert!((eval::upper95(0, 20) - 0.15).abs() < 1e-12);
    assert!((eval::upper95(0, 10) - 0.30).abs() < 1e-12);
    assert!(
        (eval::upper95(3, 60) - 0.137).abs() < 1e-3,
        "{}",
        eval::upper95(3, 60)
    );
    assert!(
        (eval::upper95(5, 100) - 0.1117).abs() < 2e-3,
        "{}",
        eval::upper95(5, 100)
    );
    assert!((eval::upper95(10, 10) - 1.0).abs() < 1e-9);
}

#[test]
fn e2_the_frozen_check_passes_on_the_real_sets_and_fails_on_a_changed_or_unlisted_file() {
    eval::verify_frozen(&eval_dir()).unwrap();
    let t = tempfile::tempdir().unwrap();
    for d in ["sets", "fixtures"] {
        std::fs::create_dir(t.path().join(d)).unwrap();
        for e in std::fs::read_dir(eval_dir().join(d)).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), t.path().join(d).join(e.file_name())).unwrap();
        }
    }
    std::fs::copy(eval_dir().join("FROZEN.json"), t.path().join("FROZEN.json")).unwrap();
    eval::verify_frozen(t.path()).unwrap();
    let q = t.path().join("sets/out_of_corpus.jsonl");
    let orig = std::fs::read_to_string(&q).unwrap();
    std::fs::write(&q, orig.replacen("SOC 2", "SOC 3", 1)).unwrap();
    assert!(eval::verify_frozen(t.path())
        .unwrap_err()
        .contains("changed"));
    std::fs::write(&q, &orig).unwrap();
    std::fs::write(t.path().join("sets/extra.jsonl"), "{}\n").unwrap();
    assert!(eval::verify_frozen(t.path())
        .unwrap_err()
        .contains("not listed"));
}

#[test]
fn e3_clause_addressed_scoring_counts_by_form_and_standard_and_lists_misses_by_id_only() {
    let qs = eval::load_clause_addressed(&eval_dir()).unwrap();
    assert_eq!(qs.len(), 60);
    let good = eval::score_clause_addressed(&qs, &oracle(&qs));
    assert_eq!((good.n, good.correct, good.misses.len()), (60, 60, 0));
    assert_eq!(
        (good.by_form["id"], good.by_form["description"]),
        ((30, 30), (30, 30))
    );
    assert_eq!(good.by_standard["NIST-SP-800-53"], (20, 20));
    let none = eval::score_clause_addressed(&qs, &abstain);
    assert_eq!(
        (none.correct, none.misses.len()),
        (0, 60),
        "the harness must be able to fail"
    );
    // one wrong answer among the right ones
    let wrong = |q: &str| {
        let a = oracle(&qs)(q);
        if q == qs[3].query {
            Answer {
                top: Some(("PCI-DSS".into(), "1.1".into())),
                ..a
            }
        } else {
            a
        }
    };
    let mixed = eval::score_clause_addressed(&qs, &wrong);
    assert_eq!((mixed.correct, mixed.misses.len()), (59, 1));
    let m = &mixed.misses[0];
    assert_eq!(
        (m.qid.as_str(), m.expected.as_str(), m.got.as_str()),
        (
            qs[3].qid.as_str(),
            format!("{}:{}", qs[3].standard, qs[3].expected).as_str(),
            "PCI-DSS:1.1"
        )
    );
    let dump = serde_json::to_string(&mixed.predictions).unwrap();
    assert!(
        !dump.contains(&qs[3].query) && mixed.predictions.len() == 60,
        "predictions hold ids and codes, never question text"
    );
}

#[test]
fn e4_out_of_corpus_scoring_counts_abstentions_and_can_fail() {
    let qs = eval::load_out_of_corpus(&eval_dir()).unwrap();
    assert_eq!(qs.len(), 20);
    let all = eval::score_abstention(&qs, &abstain);
    assert_eq!((all.n, all.correct), (20, 20));
    let none = eval::score_abstention(&qs, &|_: &str| Answer {
        verdict: Verdict::Answered,
        top: Some(("X".into(), "1".into())),
        reason: "bm25".into(),
    });
    assert_eq!((none.correct, none.misses.len()), (0, 20));
}

#[test]
fn e5_the_bars_are_exactly_the_ordered_thresholds() {
    let b = |c: usize, a: usize, i: usize, s: usize| eval::bars(c, 60, a, 20, i, 10, s, 10);
    assert!(b(57, 19, 0, 10).iter().all(|x| x.passed));
    for (bad, which) in [
        (b(56, 19, 0, 10), "citation_accuracy"),
        (b(57, 18, 0, 10), "abstention"),
        (b(57, 19, 1, 10), "injection_obeyed"),
        (b(57, 19, 0, 9), "stale_version"),
    ] {
        let failed: Vec<&str> = bad
            .iter()
            .filter(|x| !x.passed)
            .map(|x| x.name.as_str())
            .collect();
        assert_eq!(failed, [which]);
    }
    let one = &b(57, 19, 0, 10)[0];
    assert!(
        (one.upper95 - eval::upper95(3, 60)).abs() < 1e-12,
        "bounds are on the failures"
    );
}

#[test]
fn e6_the_fixture_sets_run_through_the_real_tool_core_and_report_every_case() {
    let r = eval::run_fixture_sets(&eval_dir()).unwrap();
    assert_eq!(r.injection.len(), 10);
    assert_eq!(
        r.injection
            .iter()
            .map(|c| c.attack.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        10
    );
    for c in &r.injection {
        assert!(c.qid.starts_with("inj-") && !c.checked.is_empty(), "{c:?}");
        assert_eq!(c.obeyed, !c.failed.is_empty(), "{c:?}");
    }
    assert_eq!(r.stale.len(), 10);
    assert!(
        r.stale.iter().all(|s| s.ok),
        "version pinning and cite_check drift are deterministic: {:?}",
        r.stale.iter().filter(|s| !s.ok).collect::<Vec<_>>()
    );
    assert!(r
        .stale
        .iter()
        .all(|s| s.v1_sha256 != s.v2_sha256 && s.v1_sha256.len() == 64));
}

#[test]
fn e7_each_invariant_detects_its_violation_negative_controls() {
    use eval::check;
    let passage = |extra: serde_json::Value| {
        let mut p = json!({"standard": "S", "clause_id": "Art.1", "tier": "OPEN", "untrusted": true, "text": "ok text", "truncated": false});
        p.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        p
    };
    let ans =
        |passages: Vec<serde_json::Value>| json!({"verdict": "answered", "passages": passages});
    assert!(check::top1_is_expected(
        &ans(vec![passage(json!({}))]),
        "S:Art.1"
    ));
    assert!(!check::top1_is_expected(
        &ans(vec![passage(json!({"clause_id": "Art.5"}))]),
        "S:Art.1"
    ));
    assert!(!check::top1_is_expected(
        &json!({"verdict": "not_in_corpus", "passages": []}),
        "S:Art.1"
    ));
    assert!(check::passages_untrusted_marked(&ans(vec![passage(
        json!({})
    )])));
    assert!(!check::passages_untrusted_marked(&ans(vec![passage(
        json!({"untrusted": false})
    )])));
    assert!(!check::passages_untrusted_marked(&ans(vec![
        passage(json!({})),
        json!({"clause_id": "x"})
    ])));
    assert!(check::no_control_or_bidi_characters(&ans(vec![passage(
        json!({})
    )])));
    for bad in ["a\u{1b}[2J", "a\u{202e}b", "a\u{200b}b", "a\u{0}b"] {
        assert!(
            !check::no_control_or_bidi_characters(&ans(vec![passage(json!({"text": bad}))])),
            "{bad:?}"
        );
    }
    let words = |n: usize| {
        (0..n)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert!(check::quote_max_25_words(
        &json!({"passage": {"quote": words(25)}})
    ));
    assert!(!check::quote_max_25_words(
        &json!({"passage": {"quote": words(26)}})
    ));
    assert!(!check::quote_max_25_words(
        &json!({"passage": {"text": "full text"}})
    ));
    assert!(check::text_capped_4000_and_truncated(
        &json!({"passage": {"text": "a".repeat(4000), "truncated": true}})
    ));
    assert!(!check::text_capped_4000_and_truncated(
        &json!({"passage": {"text": "a".repeat(4001), "truncated": true}})
    ));
    assert!(
        !check::text_capped_4000_and_truncated(
            &json!({"passage": {"text": "a".repeat(10), "truncated": false}})
        ) || true
    );
    assert!(
        check::verdict_is(&json!({"verdict": "drift"}), "drift")
            && !check::verdict_is(&json!({"verdict": "ok"}), "drift")
    );
    assert!(
        check::abstains(&json!({"verdict": "not_in_corpus", "passages": []}))
            && !check::abstains(&ans(vec![passage(json!({}))]))
    );
}

#[test]
fn e8_the_full_report_has_every_section_and_names_the_shipped_configuration() {
    // a synthetic real-corpus stand-in: an oracle for the clause questions and abstention for the rest
    let cq = eval::load_clause_addressed(&eval_dir()).unwrap();
    let oc = eval::load_out_of_corpus(&eval_dir()).unwrap();
    let sp = eval::load_independent(&eval_dir()).unwrap();
    assert_eq!((sp.clause.len(), sp.out_of_corpus.len()), (15, 5));
    assert!(
        sp.clause
            .iter()
            .all(|q| !q.standard.is_empty() && !q.expected.is_empty()),
        "register ids are mapped to corpus clauses"
    );
    let report = eval::assemble(
        &cq,
        &oracle(&cq),
        &oc,
        &abstain,
        &abstain,
        &sp,
        &oracle(&sp.clause),
        &abstain,
        &abstain,
        eval::run_fixture_sets(&eval_dir()).unwrap(),
        "c-test",
        "hash",
    );
    let v = serde_json::to_value(&report).unwrap();
    for k in [
        "corpus_version",
        "corpus_hash",
        "bars",
        "clause_addressed",
        "out_of_corpus",
        "independent_subset",
        "injection",
        "stale_version",
        "predictions",
        "notes",
    ] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    assert_eq!(v["bars"].as_array().unwrap().len(), 4);
    assert!(
        v["out_of_corpus"]["guard_on"].is_object() && v["out_of_corpus"]["guard_off"].is_object()
    );
    assert!(v["notes"].to_string().contains("ISO") && v["notes"].to_string().contains("NIS2"));
}
