//! R1 task 3 (first half): the question sets and fixtures are written and hash-frozen BEFORE any retrieval code exists.
//! This test pins their composition and their sha256. The git-history checks (the freeze commit predates retrieval code and is recorded in the
//! plan) live in tools/controls/tests/test_r1_freeze.py, because git is not usable inside the build container (the repo is a worktree).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::chunk::{self, Format};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn eval(rel: &str) -> PathBuf {
    crate_dir().join("eval").join(rel)
}
fn jsonl(rel: &str) -> Vec<Value> {
    std::fs::read_to_string(eval(rel))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
fn sha(p: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(p).unwrap()))
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("missing {k} in {v}"))
}
fn manifest_ids() -> BTreeSet<(String, String)> {
    let p = crate_dir().join("../../docs/evidence/r1/manifest-c2026-11-13.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["clauses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (s(c, "standard").to_string(), s(c, "id").to_string()))
        .collect()
}

#[test]
fn f1_sixty_clause_addressed_questions_with_the_agreed_mix_and_real_expected_clauses() {
    let q = jsonl("sets/clause_addressed.jsonl");
    assert_eq!(q.len(), 60);
    let mut by: BTreeMap<&str, usize> = BTreeMap::new();
    let (mut ids, mut descs) = (0, 0);
    for x in &q {
        *by.entry(s(x, "standard")).or_default() += 1;
        match s(x, "form") {
            "id" => ids += 1,
            "description" => descs += 1,
            f => panic!("form {f}"),
        }
    }
    assert_eq!((ids, descs), (30, 30));
    assert_eq!(
        by,
        BTreeMap::from([
            ("DORA-RTS", 8),
            ("EU-AI-ACT", 10),
            ("HIPAA-SECURITY-RULE", 7),
            ("NIST-SP-800-53", 20),
            ("PCI-DSS", 15)
        ])
    );
    let qids: BTreeSet<&str> = q.iter().map(|x| s(x, "qid")).collect();
    assert_eq!(qids.len(), 60);
    let have = manifest_ids();
    for x in &q {
        assert!(
            have.contains(&(s(x, "standard").to_string(), s(x, "expected").to_string())),
            "expected clause not in the sealed corpus: {x}"
        );
    }
}

#[test]
fn f2_id_questions_name_their_clause_and_description_questions_do_not() {
    for x in jsonl("sets/clause_addressed.jsonl") {
        let (query, id) = (s(&x, "query"), s(&x, "expected"));
        let bare = id.trim_start_matches("Art.");
        let names_it = query.contains(id)
            || (id.starts_with("Art.") && query.contains(&format!("Article {bare}")));
        match s(&x, "form") {
            "id" => assert!(names_it, "an id question must name its clause: {x}"),
            _ => {
                assert!(
                    !query.contains(id),
                    "a description question must not contain the clause id: {x}"
                );
                assert!(
                    !(id.starts_with("Art.") && query.contains(&format!("Article {bare}"))),
                    "{x}"
                );
            }
        }
    }
}

#[test]
fn f3_twenty_out_of_corpus_questions_cover_the_named_gaps() {
    let q = jsonl("sets/out_of_corpus.jsonl");
    assert_eq!(q.len(), 20);
    assert_eq!(
        q.iter().map(|x| s(x, "qid")).collect::<BTreeSet<_>>().len(),
        20
    );
    let all: String = q
        .iter()
        .map(|x| s(x, "query"))
        .collect::<Vec<_>>()
        .join(" | ");
    for needle in [
        "SOC 2",
        "ISO/IEC 27001",
        "ISO/IEC 42001",
        "HITRUST",
        "GDPR",
        "CMMC",
        "NIS2",
        "CNSA 2.0",
        "800-171",
        "NYDFS",
        "AU-99",
        "99.9.9",
        "Article 150",
        "Article 77",
    ] {
        assert!(
            all.contains(needle),
            "the out-of-corpus set must include {needle}"
        );
    }
}

#[test]
fn f4_injection_and_stale_sets_and_their_fixtures() {
    let inj = jsonl("sets/injection.jsonl");
    assert_eq!(inj.len(), 10);
    assert_eq!(
        inj.iter()
            .map(|x| s(x, "attack"))
            .collect::<BTreeSet<_>>()
            .len(),
        10,
        "ten different attacks"
    );
    for x in &inj {
        assert!(
            [
                "search",
                "lookup_clause",
                "cite_check",
                "list_tools",
                "call_tool"
            ]
            .contains(&s(x, "tool")),
            "{x}"
        );
        assert!(
            x["invariants"].as_array().is_some_and(|a| !a.is_empty()),
            "{x}"
        );
    }
    let inj_clauses = chunk::chunk(
        Format::EuText,
        &std::fs::read_to_string(eval("fixtures/inject_std.txt")).unwrap(),
    )
    .unwrap();
    assert_eq!(inj_clauses.len(), 11);
    let lic = chunk::chunk(
        Format::PciText,
        &std::fs::read_to_string(eval("fixtures/inject_licensed.txt")).unwrap(),
    )
    .unwrap();
    assert!(
        lic.iter()
            .any(|c| c.id == "1.1" && c.text.split_whitespace().count() > 60),
        "the licensed fixture clause must be longer than the 25-word limit"
    );
    let st = jsonl("sets/stale_version.jsonl");
    assert_eq!(st.len(), 10);
    let v1 = chunk::chunk(
        Format::EuText,
        &std::fs::read_to_string(eval("fixtures/stale_v1.txt")).unwrap(),
    )
    .unwrap();
    let v2 = chunk::chunk(
        Format::EuText,
        &std::fs::read_to_string(eval("fixtures/stale_v2.txt")).unwrap(),
    )
    .unwrap();
    assert_eq!((v1.len(), v2.len()), (12, 12));
    let differing: Vec<&str> = v1
        .iter()
        .zip(&v2)
        .filter(|(a, b)| a.text != b.text)
        .map(|(a, _)| a.id.as_str())
        .collect();
    assert_eq!(
        differing.len(),
        10,
        "exactly ten clauses differ between the two stale-version fixtures"
    );
    for x in &st {
        assert!(differing.contains(&s(x, "clause")), "{x}");
        assert!(
            v1.iter()
                .any(|c| c.id == s(x, "clause") && c.text.contains(s(x, "v1_contains"))),
            "{x}"
        );
        assert!(
            v2.iter()
                .any(|c| c.id == s(x, "clause") && c.text.contains(s(x, "v2_contains"))),
            "{x}"
        );
    }
}

#[test]
fn f5_independent_subset_is_kept_byte_for_byte_and_maps_to_real_clauses() {
    let p = eval("sets/independent_questions.json");
    assert_eq!(
        sha(&p),
        "c5f2258b5bc3a3e0673ad80a74dd149258a4f2efa85bfbc4a75631e09af4b49c",
        "the reviewer's file must not be edited"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    assert_eq!(
        (
            v["clause_addressed"].as_array().unwrap().len(),
            v["out_of_corpus"].as_array().unwrap().len()
        ),
        (15, 5)
    );
    let map: Value =
        serde_json::from_str(&std::fs::read_to_string(eval("sets/register_map.json")).unwrap())
            .unwrap();
    let have = manifest_ids();
    assert_eq!(
        map.as_object().unwrap().len(),
        17,
        "all 17 E1 register ids are mapped"
    );
    for (k, t) in map.as_object().unwrap() {
        assert!(
            have.contains(&(
                t[0].as_str().unwrap().to_string(),
                t[1].as_str().unwrap().to_string()
            )),
            "{k} maps to a clause that is not in the corpus"
        );
    }
    for q in v["clause_addressed"].as_array().unwrap() {
        assert!(map.get(s(q, "expect")).is_some(), "no mapping for {q}");
    }
}

#[test]
fn f6_every_file_under_eval_is_hash_frozen_in_frozen_json_and_nothing_is_unlisted() {
    let fz: Value =
        serde_json::from_str(&std::fs::read_to_string(eval("FROZEN.json")).unwrap()).unwrap();
    let files = fz["files"].as_object().unwrap();
    assert_eq!(fz["plan_commit"].as_str().unwrap(), "ecfa560");
    let mut listed = BTreeSet::new();
    for (rel, h) in files {
        assert_eq!(
            sha(&eval(rel)),
            h.as_str().unwrap(),
            "{rel} changed after the freeze"
        );
        listed.insert(rel.clone());
    }
    let mut on_disk = BTreeSet::new();
    for dir in ["sets", "fixtures"] {
        for e in std::fs::read_dir(eval(dir)).unwrap() {
            on_disk.insert(format!(
                "{dir}/{}",
                e.unwrap().file_name().to_str().unwrap()
            ));
        }
    }
    assert_eq!(
        listed, on_disk,
        "every set and fixture file must be listed and hashed"
    );
}
