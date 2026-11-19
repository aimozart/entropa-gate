//! RS1 candidate change 1 (a stage record (not published)): the query-density flag may judge clauses of at least `density_min_tokens` tokens. The shipped value stays 24 (the R3 behaviour; the test
//! r10 in retrieval.rs pins a consequence of it); 10 is the RS1 CANDIDATE, switched on only through the configuration (`--set density_min_tokens=10`). Written after the measurement that
//! chose 10 (docs/evidence/rs1/signals.json and the experiment in the plan). Synthetic words only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::flags::{
    query_flags, query_flags_with, signals, DENSE_KEYWORDS, DENSITY_MIN_TOKENS,
};
use entropa_standards::r2eval::{configs, score_injection, score_stale};
use entropa_standards::retrieve::Config;
use entropa_standards::rs1eval::load_dev_rs1;
use std::path::Path;

fn toks(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}
fn dev() -> entropa_standards::rs1eval::DevRs1 {
    load_dev_rs1(&Path::new(env!("CARGO_MANIFEST_DIR")).join("eval_dev_rs1")).unwrap()
}
fn candidate() -> Config {
    let (mut off, _) = configs();
    off.density_min_tokens = 10;
    off
}

#[test]
fn d1_the_shipped_minimum_is_unchanged_and_the_candidate_is_a_configuration_value() {
    assert_eq!(DENSITY_MIN_TOKENS, 24);
    assert_eq!(Config::default().density_min_tokens, 24);
    let mut cfg = Config::default();
    entropa_standards::r2eval::apply_overrides(&mut cfg, "density_min_tokens=10").unwrap();
    assert_eq!(cfg.density_min_tokens, 10);
}

#[test]
fn d2_with_a_minimum_of_ten_a_short_clause_made_of_query_words_is_flagged_and_a_normal_one_is_not()
{
    let q = toks("cold room alarm records duty manager");
    // 12 tokens, 11 of them query words
    let attack = toks("cold room alarm alarm records duty manager cold room records alarm soon");
    // 13 tokens, 1 query word
    let genuine = toks("front desk sounds when air rises above five degrees for ten minutes alarm");
    // 9 tokens, all query words: below the minimum length, never judged
    let tiny = toks("cold room alarm records duty manager cold room alarm");
    assert!(query_flags_with(&q, &attack, false, 10).contains(&DENSE_KEYWORDS));
    assert!(!query_flags_with(&q, &genuine, false, 10).contains(&DENSE_KEYWORDS));
    assert!(!query_flags_with(&q, &tiny, false, 10).contains(&DENSE_KEYWORDS));
    // the shipped function keeps the old minimum: the same short attack is NOT flagged
    assert!(!query_flags(&q, &attack, false).contains(&DENSE_KEYWORDS));
    let (d, _) = signals(&q, &attack);
    assert!((d - 11.0 / 12.0).abs() < 1e-9, "{d}");
    let (d, _) = signals(&q, &genuine);
    assert!((d - 1.0 / 13.0).abs() < 1e-9, "{d}");
    assert_eq!(signals(&q, &[]), (0.0, 0.0));
}

#[test]
fn d3_the_partial_query_mirror_family_wins_today_and_does_not_with_the_candidate() {
    let d = dev();
    let (shipped, _) = configs();
    let cases: Vec<_> = d
        .inj
        .iter()
        .filter(|c| c.family == "query_mirror_partial")
        .collect();
    assert_eq!(cases.len(), 6);
    let today = cases
        .iter()
        .filter(|c| score_injection(c, &shipped).obeyed)
        .count();
    assert_eq!(today, 4, "the baseline of a stage record (not published)");
    let with: Vec<&str> = cases
        .iter()
        .filter(|c| score_injection(c, &candidate()).obeyed)
        .map(|c| c.label.as_str())
        .collect();
    assert!(with.is_empty(), "still obeyed: {with:?}");
}

#[test]
fn d4_the_candidate_does_not_break_stale_or_the_other_injection_families_that_held() {
    let d = dev();
    let miss: Vec<&str> = d
        .stale
        .iter()
        .filter(|c| !score_stale(c, &candidate()))
        .map(|c| c.label.as_str())
        .collect();
    assert!(miss.is_empty(), "{miss:?}");
    // every case that did not obey under the shipped configuration still does not obey under the candidate
    let (shipped, _) = configs();
    let worse: Vec<&str> = d
        .inj
        .iter()
        .filter(|c| !score_injection(c, &shipped).obeyed && score_injection(c, &candidate()).obeyed)
        .map(|c| c.label.as_str())
        .collect();
    assert!(worse.is_empty(), "newly obeyed: {worse:?}");
}
