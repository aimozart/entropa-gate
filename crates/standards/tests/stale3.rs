//! R3 (the reviewer's order after task 3): a version-pinned lookup stays exact on tiny one-clause corpora. The DEV3 case s3-09 ("How many times are
//! disks wiped before disposal?") was refused by the old idf-weighted coverage floor of 0.3 (the query holds words the one clause does not);
//! the shipped floor is 0.25 and the content-word gate (two distinct words, 0.4 of the query's content words) still guards the answer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{text_sha256, Clause, Tier};
use entropa_standards::retrieve::{Config, Retriever, Verdict};

fn c(ver: &str, text: &str) -> Clause {
    Clause {
        standard: "SYN-DEV".into(),
        std_version: ver.into(),
        id: "Z-9".into(),
        tier: Tier::Open,
        text: text.into(),
        text_sha256: text_sha256(text),
    }
}
fn rt() -> Retriever {
    let mut r = Retriever::from_clauses(
        "v1",
        &"3".repeat(64),
        vec![c("1", "Disposal. Wipe disks once before disposal.")],
    );
    r.add_clauses(
        "v2",
        &"4".repeat(64),
        vec![c("2", "Disposal. Wipe disks three times before disposal.")],
    );
    r
}

#[test]
fn k1_a_pinned_lookup_on_a_one_clause_corpus_returns_the_pinned_text() {
    for (ver, text) in [
        ("v1", "Disposal. Wipe disks once before disposal."),
        ("v2", "Disposal. Wipe disks three times before disposal."),
    ] {
        let r = rt().search(
            "How many times are disks wiped before disposal?",
            Some(ver),
            3,
            &Config::default(),
        );
        assert_eq!(r.verdict, Verdict::Answered, "{ver}: {}", r.reason);
        assert_eq!(r.passages[0].text_sha256, text_sha256(text));
    }
}

#[test]
fn k2_the_old_floor_would_have_refused_it_and_the_content_gate_still_refuses_an_unrelated_question()
{
    let old = Config {
        coverage_min: 0.3,
        ..Config::default()
    };
    let r = rt().search(
        "How many times are disks wiped before disposal?",
        Some("v1"),
        3,
        &old,
    );
    assert_eq!(
        r.verdict,
        Verdict::NotInCorpus,
        "documents why the floor moved"
    );
    let r = rt().search(
        "What is the capital city of Australia and how many people live there?",
        Some("v1"),
        3,
        &Config::default(),
    );
    assert_eq!(r.verdict, Verdict::NotInCorpus);
}
