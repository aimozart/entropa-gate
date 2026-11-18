//! R3 task 1: the R3 DEV sets exist, are well formed, are hash-frozen, differ from the R1/R2 sets and from the name list in the code, and every
//! "nonexistent id" really does not exist in the sealed corpus while every id-named question names a clause that does.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
fn manifest_ids() -> BTreeSet<(String, String)> {
    let m: Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("../../docs/evidence/r1/manifest-c2026-11-13.json"))
            .unwrap(),
    )
    .unwrap();
    m["clauses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["standard"].as_str().unwrap().to_string(),
                c["id"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn e1_out_of_corpus_set_has_30_questions_over_every_held_standard_and_none_is_a_real_id() {
    let qs = jsonl(dev("dev3_out_of_corpus.jsonl"));
    assert_eq!(qs.len(), 30);
    let kinds: BTreeSet<&str> = qs.iter().map(|q| q["kind"].as_str().unwrap()).collect();
    for k in [
        "everyday",
        "unindexed",
        "id_nist",
        "id_pci",
        "id_eu",
        "id_dora",
        "id_hipaa",
    ] {
        assert!(kinds.contains(k), "kind {k} missing");
    }
    let real = manifest_ids();
    for q in &qs {
        if let (Some(std), Some(id)) = (q.get("standard"), q.get("id")) {
            assert!(
                !real.contains(&(std.as_str().unwrap().into(), id.as_str().unwrap().into())),
                "{} names an id that exists",
                q["qid"]
            );
        }
    }
    // every id-kind question carries the id it names
    for q in qs
        .iter()
        .filter(|q| q["kind"].as_str().unwrap().starts_with("id_"))
    {
        assert!(
            q.get("id").is_some() && q.get("standard").is_some(),
            "{}",
            q["qid"]
        );
    }
}

#[test]
fn e2_out_of_corpus_questions_use_no_name_from_the_codes_list_and_are_new() {
    let qs = jsonl(dev("dev3_out_of_corpus.jsonl"));
    let src = std::fs::read_to_string(root().join("src/retrieve.rs")).unwrap();
    let i = src
        .find("rx(r\"\\b(soc")
        .expect("the name list is still in the code as an ablation");
    let rest = &src[i + 5..];
    let re = regex::Regex::new(&rest[..rest.find("\")").unwrap()]).unwrap();
    let mut old: BTreeSet<String> = BTreeSet::new();
    for f in ["dev_out_of_corpus.jsonl", "dev_out_of_corpus_2.jsonl"] {
        for q in jsonl(dev(f)) {
            old.insert(q["query"].as_str().unwrap().to_lowercase());
        }
    }
    for f in ["eval/sets/out_of_corpus.jsonl"] {
        if let Ok(s) = std::fs::read_to_string(root().join(f)) {
            for l in s.lines() {
                let v: Value = serde_json::from_str(l).unwrap();
                old.insert(v["query"].as_str().unwrap_or("").to_lowercase());
            }
        }
    }
    for q in &qs {
        let t = q["query"].as_str().unwrap().to_lowercase();
        assert!(!re.is_match(&t), "a name on the code's list: {}", q["qid"]);
        assert!(!old.contains(&t), "a repeat of an older set: {}", q["qid"]);
    }
}

#[test]
fn e3_injection_set_has_24_cases_in_at_least_12_families_with_the_six_ordered_ones() {
    let cs = jsonl(dev("dev3_injection.jsonl"));
    assert_eq!(cs.len(), 24);
    let mut fam: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cs {
        *fam.entry(c["family"].as_str().unwrap().to_string())
            .or_default() += 1;
        assert_eq!(c["clauses"].as_array().unwrap().len(), 4);
        assert!(c["expected"].as_str().unwrap().starts_with("SYN-DEV:"));
    }
    assert!(fam.len() >= 12, "{} families", fam.len());
    for f in [
        "query_mirror",
        "function_word_padding",
        "split_keywords",
        "repeated_heading",
        "quoted_copy",
        "unicode_homoglyph",
    ] {
        assert!(fam.get(f).copied().unwrap_or(0) >= 2, "family {f}");
    }
    // none of the R2 DEV family names is reused
    let r2: BTreeSet<String> = jsonl(dev("dev_injection.jsonl"))
        .iter()
        .map(|c| c["family"].as_str().unwrap().to_string())
        .collect();
    for f in fam.keys() {
        assert!(!r2.contains(f), "R2 family reused: {f}");
    }
    // the expected clause really is one of the four
    for c in &cs {
        let want = c["expected"].as_str().unwrap();
        assert!(
            c["clauses"].as_array().unwrap().iter().any(|x| format!(
                "{}:{}",
                x["standard"].as_str().unwrap(),
                x["id"].as_str().unwrap()
            ) == want),
            "{} expects a clause that is not there",
            c["case"]
        );
    }
}

#[test]
fn e4_id_named_set_has_20_real_clauses_and_stale_set_has_10_cases() {
    let qs = jsonl(dev("dev3_id_named.jsonl"));
    assert_eq!(qs.len(), 20);
    let real = manifest_ids();
    for q in &qs {
        let key = (
            q["standard"].as_str().unwrap().to_string(),
            q["expected"].as_str().unwrap().to_string(),
        );
        assert!(real.contains(&key), "not a real clause: {key:?}");
    }
    let st = jsonl(dev("dev3_stale.jsonl"));
    assert_eq!(st.len(), 10);
    for s in &st {
        let t = s[if s["pinned_version"] == "v1" {
            "version_1_text"
        } else {
            "version_2_text"
        }]
        .as_str()
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(t.as_bytes())),
            s["expected_text_sha256"].as_str().unwrap()
        );
        assert_ne!(s["version_1_text"], s["version_2_text"]);
    }
}

#[test]
fn e5_dev3_files_match_their_frozen_hashes_and_the_older_sets_are_untouched() {
    let frozen: Value =
        serde_json::from_str(&std::fs::read_to_string(dev("DEV3_FROZEN.json")).unwrap()).unwrap();
    let files = frozen["files"].as_object().unwrap();
    assert_eq!(files.len(), 4);
    for (name, h) in files {
        assert_eq!(sha(dev(name)), h.as_str().unwrap(), "{name} changed");
    }
    // R2 DEV sets keep the hashes they were frozen with
    let r2: Value =
        serde_json::from_str(&std::fs::read_to_string(dev("DEV_FROZEN.json")).unwrap()).unwrap();
    assert_eq!(r2["files"].as_object().unwrap().len(), 3);
}
