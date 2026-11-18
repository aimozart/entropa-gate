//! R1 task 5: citation-bound guardrails. Each E1 register row and three real guardrails of ours cite a clause by (standard, clause id) with the
//! sha256 of that clause's text in a named corpus version. The check is a deterministic lookup by id in the sealed manifest; it never searches.
//! If a cited clause's text changes in a newer corpus version, the check fails (drift).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::citations::{self, Finding};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|_| panic!("cannot read {rel}"))
}
fn manifest() -> String {
    read("docs/evidence/r1/manifest-c2026-11-13.json")
}
fn cites() -> citations::Citations {
    citations::parse(&read("compliance/citations.json")).unwrap()
}

#[test]
fn k1_every_e1_register_row_is_bound_and_the_binding_matches_the_frozen_register_map() {
    let c = cites();
    let ids: BTreeSet<&str> = c
        .register_rows
        .iter()
        .map(|r| r.register_id.as_str())
        .collect();
    let reg: Value =
        serde_json::from_str(&read("crates/standards/eval/sets/register_map.json")).unwrap();
    assert_eq!(
        ids,
        reg.as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(c.register_rows.len(), 17);
    for r in &c.register_rows {
        let t = &reg[&r.register_id];
        assert_eq!(
            (r.cite.standard.as_str(), r.cite.clause.as_str()),
            (t[0].as_str().unwrap(), t[1].as_str().unwrap()),
            "{}",
            r.register_id
        );
    }
    let e1: Value = serde_json::from_str(&read("compliance/controls-register.json")).unwrap();
    let e1_ids: BTreeSet<&str> = e1["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, e1_ids, "exactly the E1 register ids");
}

#[test]
fn k2_three_real_guardrails_each_cite_at_least_one_clause_and_their_files_and_markers_exist() {
    let c = cites();
    assert_eq!(c.guardrails.len(), 3);
    let kinds: BTreeSet<&str> = c.guardrails.iter().map(|g| g.kind.as_str()).collect();
    assert_eq!(
        kinds,
        BTreeSet::from(["cedar_rule", "input_validation", "canary_scan"])
    );
    for g in &c.guardrails {
        assert!(!g.cites.is_empty(), "{}", g.id);
    }
    assert_eq!(citations::check_subjects(&c, &repo()), vec![]);
}

#[test]
fn k3_the_citations_name_the_corpus_version_and_hash_and_every_hash_is_a_sha256() {
    let c = cites();
    let m: Value = serde_json::from_str(&manifest()).unwrap();
    assert_eq!(
        (c.corpus_version.as_str(), c.corpus_hash.as_str()),
        (
            m["corpus_version"].as_str().unwrap(),
            m["corpus_hash"].as_str().unwrap()
        )
    );
    for r in c.all_refs() {
        assert!(
            r.text_sha256.len() == 64 && r.text_sha256.chars().all(|x| x.is_ascii_hexdigit()),
            "{r:?}"
        );
    }
}

#[test]
fn k4_against_the_sealed_manifest_nothing_has_drifted() {
    let lookup = citations::manifest_lookup(&manifest()).unwrap();
    assert_eq!(citations::check(&cites(), &*lookup), vec![]);
}

#[test]
fn k5_the_drift_check_bites_a_changed_clause_text_is_reported_for_exactly_its_citations() {
    let c = cites();
    let mut m: Value = serde_json::from_str(&manifest()).unwrap();
    // a newer corpus version in which NIST AC-3 reads differently
    for cl in m["clauses"].as_array_mut().unwrap() {
        if cl["standard"] == "NIST-SP-800-53" && cl["id"] == "AC-3" {
            cl["text_sha256"] = Value::String("0".repeat(64));
        }
    }
    let lookup = citations::manifest_lookup(&m.to_string()).unwrap();
    let findings = citations::check(&c, &*lookup);
    let who: Vec<String> = findings.iter().map(|f| f.subject().to_string()).collect();
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| matches!(f, Finding::Drift { standard, clause, .. } if standard == "NIST-SP-800-53" && clause == "AC-3")), "{findings:?}");
    let expected: Vec<String> = c
        .guardrails
        .iter()
        .filter(|g| g.cites.iter().any(|x| x.clause == "AC-3"))
        .map(|g| g.id.clone())
        .collect();
    for e in &expected {
        assert!(
            who.contains(e),
            "{e} cites AC-3 and must be flagged: {who:?}"
        );
    }
    // a changed PCI clause flags the register rows that cite it, and nothing else
    let mut m2: Value = serde_json::from_str(&manifest()).unwrap();
    for cl in m2["clauses"].as_array_mut().unwrap() {
        if cl["standard"] == "PCI-DSS" && cl["id"] == "10.3.4" {
            cl["text_sha256"] = Value::String("1".repeat(64));
        }
    }
    let f2 = citations::check(&c, &*citations::manifest_lookup(&m2.to_string()).unwrap());
    assert_eq!(
        f2.iter()
            .map(|f| f.subject().to_string())
            .collect::<Vec<_>>(),
        ["PCI-10-3-4"]
    );
}

#[test]
fn k6_a_cited_clause_that_disappears_is_reported_unknown_not_ok() {
    let mut m: Value = serde_json::from_str(&manifest()).unwrap();
    m["clauses"]
        .as_array_mut()
        .unwrap()
        .retain(|c| !(c["standard"] == "EU-AI-ACT" && c["id"] == "Art.19"));
    let f = citations::check(
        &cites(),
        &*citations::manifest_lookup(&m.to_string()).unwrap(),
    );
    assert_eq!(f.len(), 1);
    assert!(
        matches!(&f[0], Finding::Unknown { clause, .. } if clause == "Art.19"),
        "{f:?}"
    );
}

#[test]
fn k7_a_missing_guardrail_file_or_marker_is_a_finding() {
    let t = tempfile::tempdir().unwrap();
    let c = cites();
    let none = citations::check_subjects(&c, t.path());
    assert_eq!(none.len(), 3, "{none:?}");
    for g in &c.guardrails {
        let p = t.path().join(&g.file);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "a file without the marker\n").unwrap();
    }
    assert!(citations::check_subjects(&c, t.path())
        .iter()
        .all(|f| matches!(f, Finding::MarkerMissing { .. })));
    for g in &c.guardrails {
        std::fs::write(t.path().join(&g.file), format!("// {}\n", g.marker)).unwrap();
    }
    assert_eq!(citations::check_subjects(&c, t.path()), vec![]);
}

#[test]
fn k8_the_binding_is_by_clause_id_the_citation_code_never_searches() {
    let src =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/citations.rs"))
            .unwrap();
    for banned in [
        "Retriever",
        "search(",
        "bm25",
        "tokens(",
        "Config",
        "text::",
    ] {
        assert!(
            !src.contains(banned),
            "citations.rs must be exact-id lookups only: found {banned}"
        );
    }
}

#[test]
fn k9_a_malformed_citations_file_is_refused() {
    for bad in [
        "",
        "{",
        "[]",
        r#"{"citations_version":1}"#,
        r#"{"citations_version":2,"corpus_version":"v","corpus_hash":"h","register_rows":[],"guardrails":[]}"#,
    ] {
        assert!(citations::parse(bad).is_err(), "{bad}");
    }
    let mut v: Value = serde_json::from_str(&read("compliance/citations.json")).unwrap();
    v["register_rows"][0]["text_sha256"] = Value::String("not a hash".into());
    assert!(citations::parse(&v.to_string()).is_err());
}
