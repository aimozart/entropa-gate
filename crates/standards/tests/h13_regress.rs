//! H1.3 regression tests for violations found by the property tests (h13_props.rs). Each was red on the code at rag-r3 (b439e62).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{text_sha256, Clause, Tier};
use entropa_standards::retrieve::{Config, Retriever, Verdict};

fn c(std: &str, id: &str, text: &str) -> Clause {
    Clause {
        standard: std.into(),
        std_version: "1".into(),
        id: id.into(),
        tier: Tier::Open,
        text: text.into(),
        text_sha256: text_sha256(text),
    }
}
fn rt() -> Retriever {
    Retriever::from_clauses(
        "v",
        &"0".repeat(64),
        vec![
            c(
                "NIST-SP-800-53",
                "SR-10",
                "Supply chain. Employ supply chain protections.",
            ),
            c(
                "NIST-SP-800-53",
                "AC-10",
                "Concurrent session control. Limit the number of sessions.",
            ),
            c(
                "NIST-SP-800-53",
                "AC-2(4)",
                "Automated audit actions. Audit account creation.",
            ),
            c(
                "PCI-DSS",
                "8.3",
                "Strong authentication for users and administrators is established.",
            ),
            c(
                "PCI-DSS",
                "8.3.6",
                "Passwords meet a minimum level of complexity.",
            ),
            c(
                "EU-AI-ACT",
                "Art.1",
                "Subject matter. This regulation lays down rules.",
            ),
            c(
                "EU-AI-ACT",
                "Annex III",
                "High-risk AI systems referred to in the article.",
            ),
            c(
                "DORA-RTS",
                "Art.1",
                "Overall risk profile and complexity. Take account of the size.",
            ),
            c(
                "HIPAA-SECURITY-RULE",
                "164.312(a)",
                "Access control. Implement technical policies.",
            ),
            c(
                "HIPAA-SECURITY-RULE",
                "164.312",
                "Technical safeguards. Section text.",
            ),
        ],
    )
}
fn ask(q: &str) -> (Verdict, String, Vec<String>) {
    let r = rt().search(q, Some("v"), 5, &Config::default());
    let ids = r.passages.iter().map(|p| p.clause_id.clone()).collect();
    (r.verdict, r.reason, ids)
}

/// H13-V1 (I2): an id whose number is LONGER than any held id used to be read as its held prefix (SR-100 as SR-10, 8.3.100 as 8.3).
#[test]
fn v1_a_longer_number_is_not_read_as_its_held_prefix() {
    for q in [
        "What does SR-100 require?",
        "Explain AC-100.",
        "What does AC-2(40) say?",
        "What does AC-2(4)(a) say?",
        "PCI DSS requirement 8.3.100",
        "PCI DSS requirement 8.3.6.100",
        "What does 164.3123(a) require?",
        "What does Article 1000 require of the DORA RTS?",
    ] {
        let (v, why, ids) = ask(q);
        assert_eq!(v, Verdict::NotInCorpus, "{q} -> {ids:?} ({why})");
    }
}

/// H13-V2 (I3): the id keywords written in capitals (ART., ARTICLE, ANNEX) are not names of a foreign standard.
#[test]
fn v2_capitalised_id_keywords_are_not_a_foreign_standard() {
    for (q, want) in [
        ("DORA RTS ART. 1 requirement", "Art.1"),
        ("DORA RTS ARTICLE 1 requirement", "Art.1"),
        ("EU AI ACT ARTICLE 1 requirement", "Art.1"),
        ("AI Act ANNEX III requirement", "Annex III"),
        ("PCI DSS REQUIREMENT 8.3.6", "8.3.6"),
    ] {
        let (v, why, ids) = ask(q);
        assert_eq!(v, Verdict::Answered, "{q} ({why})");
        assert_eq!(ids, vec![want.to_string()], "{q}");
    }
}

/// Controls that must keep working after the fixes.
#[test]
fn v3_existing_ids_still_answer() {
    for (q, want) in [
        ("What does SR-10 require?", "SR-10"),
        ("Explain AC-10.", "AC-10"),
        ("PCI DSS requirement 8.3.6", "8.3.6"),
        ("PCI DSS requirement 8.3", "8.3"),
        ("Article 1 of the EU AI Act", "Art.1"),
        ("What does 164.312(a) require?", "164.312(a)"),
    ] {
        let (v, why, ids) = ask(q);
        assert_eq!(v, Verdict::Answered, "{q} ({why})");
        assert_eq!(ids[0], want, "{q}");
    }
}

/// H13-V3 (I3): a roman numeral after Annex (VII, III, XIV) is a number, not the name of a foreign standard.
#[test]
fn v5_a_roman_numeral_after_annex_is_not_a_foreign_standard() {
    for (q, want) in [
        ("Annex III requirement", "Annex III"),
        (
            "What does ANNEX III require, as a requirement?",
            "Annex III",
        ),
        ("AI Act Annex III control", "Annex III"),
    ] {
        let (v, why, ids) = ask(q);
        assert_eq!(v, Verdict::Answered, "{q} ({why})");
        assert_eq!(ids[0], "Annex III", "{q}");
        let _ = want;
    }
}

/// H13-V4 (store integrity): the clause's own std_version and tier are covered by the check on opening a sealed store; a clause line that says
/// a different version or a different licence tier than the manifest's source is refused.
#[test]
fn v4_a_changed_clause_tier_or_version_in_the_store_is_refused() {
    use entropa_standards::corpus::{ClauseEntry, Manifest, SourceEntry};
    use entropa_standards::seal;
    let text = "Passwords. Passwords meet a minimum level of complexity.";
    let clause = Clause {
        standard: "PCI-DSS".into(),
        std_version: "4.0.1".into(),
        id: "8.3.6".into(),
        tier: Tier::Licensed,
        text: text.into(),
        text_sha256: text_sha256(text),
    };
    let entries = vec![ClauseEntry {
        standard: "PCI-DSS".into(),
        id: "8.3.6".into(),
        text_sha256: text_sha256(text),
    }];
    let sources = vec![SourceEntry {
        standard: "PCI-DSS".into(),
        std_version: "4.0.1".into(),
        tier: Tier::Licensed,
        format: "text".into(),
        file: "p.txt".into(),
        source_sha256: "0".repeat(64),
        clauses: 1,
    }];
    let m = Manifest {
        corpus_version: "v1".into(),
        corpus_hash: Manifest::compute_hash("v1", &sources, &entries),
        sources,
        clauses: entries,
    };
    let base = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("h13-v4-{}", std::process::id()));
    let write = |name: &str, c: &Clause| {
        let d = base.join(name).join("v1");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();
        std::fs::write(
            d.join("clauses.jsonl"),
            format!("{}\n", serde_json::to_string(c).unwrap()),
        )
        .unwrap();
        base.join(name)
    };
    assert!(
        seal::open(&write("good", &clause), "v1").is_ok(),
        "the untouched store opens"
    );
    let mut open_tier = clause.clone();
    open_tier.tier = Tier::Open;
    assert!(
        seal::open(&write("tier", &open_tier), "v1").is_err(),
        "a licensed clause relabelled OPEN would return its full text"
    );
    let mut other_version = clause.clone();
    other_version.std_version = "9.9".into();
    assert!(seal::open(&write("version", &other_version), "v1").is_err());
}
