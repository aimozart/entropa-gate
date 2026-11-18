//! R2: a query that names a standard we do not hold abstains, with no list of foreign names: the rule is structural (an acronym or
//! digit-bearing name followed by a kind word such as criterion, article or control, that is not one of the held standards' own names).
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
            c("NIST-SP-800-53", "AC-2", "Account Management. Define and document the types of accounts allowed and manage them."),
            c("NIST-SP-800-53", "AU-9", "Protection of Audit Information. Protect audit information and audit logging tools from unauthorized access."),
            c("NIST-SP-800-53", "CP-9", "System Backup. Conduct backups of user-level and system-level information."),
            c("PCI-DSS", "6.1", "Processes and mechanisms for developing and maintaining secure systems are defined."),
            c("PCI-DSS", "12.3.3", "Cryptographic cipher suites and protocols in use are documented and reviewed."),
            c("EU-AI-ACT", "Art.12", "Record-keeping. High-risk AI systems shall allow automatic recording of events logs."),
        ],
    )
}
fn verdict(q: &str) -> (Verdict, String) {
    let r = rt().search(q, Some("v"), 3, &Config::default());
    (r.verdict, r.reason)
}

#[test]
fn f1_a_foreign_acronym_with_a_kind_word_abstains_even_when_an_id_shaped_token_exists_here() {
    for q in [
        "What does SOC 2 criterion CC6.1 require for logical access?",
        "Which GDPR article covers record-keeping of events?",
        "What does the CMMC practice say about audit information?",
        "What does NIS2 Article 12 require?",
        "What does ISO/IEC 27001 Annex A control 6.1 require?",
    ] {
        let (v, why) = verdict(q);
        assert_eq!(v, Verdict::NotInCorpus, "{q} ({why})");
    }
}

#[test]
fn f2_another_nist_publication_number_abstains_but_the_held_one_answers() {
    assert_eq!(
        verdict("What does NIST SP 800-171 require for audit information?").0,
        Verdict::NotInCorpus
    );
    assert_eq!(
        verdict("What does NIST SP 800-53 control AC-2 require?").0,
        Verdict::Answered
    );
}

#[test]
fn f3_held_standards_names_and_plain_acronyms_do_not_trigger_it() {
    for q in [
        "What does NIST control AC-2 require?",
        "What does PCI DSS requirement 12.3.3 say?",
        "What does the EU AI Act Article 12 require?",
        "Which clause protects audit information and audit logging tools from access?",
    ] {
        let (v, why) = verdict(q);
        assert_eq!(v, Verdict::Answered, "{q} ({why})");
    }
}

#[test]
fn f4_a_clause_id_followed_by_a_kind_word_is_not_a_foreign_standard() {
    // regression found by the R1 frozen id-named question "NIST SP 800-53 CP-9 requirements."
    for q in [
        "NIST SP 800-53 CP-9 requirements.",
        "What does AU-9 require?",
        "AC-2 control",
    ] {
        let (v, why) = verdict(q);
        assert_eq!(v, Verdict::Answered, "{q} ({why})");
    }
}
