//! R2 task 1: the DEV sets exist, are well formed, are hash-frozen, and do not overlap the R1 frozen sets or the name lists in the code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn dev(name: &str) -> PathBuf {
    root().join("eval_dev").join(name)
}
fn jsonl(p: PathBuf) -> Vec<Value> {
    std::fs::read_to_string(&p)
        .unwrap_or_else(|_| panic!("missing {}", p.display()))
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
fn sha(p: PathBuf) -> String {
    hex::encode(Sha256::digest(std::fs::read(p).unwrap()))
}

#[test]
fn d1_description_set_has_at_least_60_questions_over_real_clauses_not_in_r1() {
    let qs = jsonl(dev("dev_description.jsonl"));
    assert!(qs.len() >= 60, "{}", qs.len());
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("../../docs/evidence/r1/manifest-c2026-11-13.json"))
            .unwrap(),
    )
    .unwrap();
    let real: BTreeSet<(String, String)> = manifest["clauses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["standard"].as_str().unwrap().to_string(),
                c["id"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let r1: BTreeSet<(String, String)> = jsonl(root().join("eval/sets/clause_addressed.jsonl"))
        .iter()
        .map(|q| {
            (
                q["standard"].as_str().unwrap().to_string(),
                q["expected"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let mut seen = BTreeSet::new();
    for q in &qs {
        let key = (
            q["standard"].as_str().unwrap().to_string(),
            q["expected"].as_str().unwrap().to_string(),
        );
        assert!(real.contains(&key), "not a real clause: {key:?}");
        assert!(!r1.contains(&key), "also in the R1 frozen set: {key:?}");
        assert!(seen.insert(key), "duplicate clause");
        assert_eq!(q["form"], "description");
    }
}

#[test]
fn d2_out_of_corpus_set_has_20_questions_and_no_name_from_a_list_in_the_code() {
    let qs = jsonl(dev("dev_out_of_corpus.jsonl"));
    assert!(qs.len() >= 20, "{}", qs.len());
    let src = std::fs::read_to_string(root().join("src/retrieve.rs")).unwrap();
    if let Some(i) = src.find("rx(r\"\\b(soc") {
        let rest = &src[i + 5..];
        let pat = &rest[..rest.find("\")").unwrap()];
        let re = regex::Regex::new(pat).unwrap();
        for q in &qs {
            assert!(
                !re.is_match(&q["query"].as_str().unwrap().to_lowercase()),
                "a name on the code's list: {}",
                q["qid"]
            );
        }
    }
}

#[test]
fn d3_injection_set_covers_eight_families_with_a_four_clause_corpus_each() {
    let cs = jsonl(dev("dev_injection.jsonl"));
    assert!(cs.len() >= 20, "{}", cs.len());
    let want = [
        "stuffing_repetition",
        "keyword_block",
        "length_attack_long_decoy",
        "length_attack_long_genuine",
        "fake_supersession",
        "instruction_text",
        "id_spoof",
        "title_spoof",
        "zero_width",
    ];
    for f in want {
        assert!(
            cs.iter().filter(|c| c["family"] == f).count() >= 2,
            "family {f}"
        );
    }
    for c in &cs {
        assert_eq!(c["clauses"].as_array().unwrap().len(), 4);
        assert!(c["expected"].as_str().unwrap().starts_with("SYN-DEV:Z-"));
    }
}

#[test]
fn d4_dev_files_match_their_frozen_hashes() {
    let frozen: Value =
        serde_json::from_str(&std::fs::read_to_string(dev("DEV_FROZEN.json")).unwrap()).unwrap();
    for (name, h) in frozen["files"].as_object().unwrap() {
        assert_eq!(sha(dev(name)), h.as_str().unwrap(), "{name} changed");
    }
    assert_eq!(frozen["files"].as_object().unwrap().len(), 3);
}
