//! R3 task 3: every id-shaped token is resolved by exact lookup for ALL held standards; one that does not exist ABSTAINS (never a similar id, never
//! a text match on another clause). Version numbers and product numbers (TLS 1.2, PCI DSS 4.0) are not ids.
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
            c("NIST-SP-800-53", "AC-2(4)", "Automated Audit Actions. Automatically audit account creation, modification and removal."),
            c("NIST-SP-800-53", "SC-7", "Boundary Protection. Monitor and control communications at the external boundary of the system."),
            c("PCI-DSS", "1.2", "Network security controls are configured and maintained."),
            c("PCI-DSS", "5.1", "Processes and mechanisms for protecting all systems against malware are defined and understood."),
            c("PCI-DSS", "8.3.6", "If passwords are used as authentication factors they meet a minimum level of complexity."),
            c("EU-AI-ACT", "Art.12", "Record-keeping. High-risk AI systems shall allow automatic recording of events logs."),
            c("EU-AI-ACT", "Annex III", "High-risk AI systems referred to in the article: biometrics, critical infrastructure and education."),
            c("DORA-RTS", "Art.9", "ICT security policies cover protection and prevention of the financial entity."),
            c("HIPAA-SECURITY-RULE", "164.312(a)", "Access control. Implement technical policies for electronic information systems that maintain protected health information."),
            c("HIPAA-SECURITY-RULE", "164.312(e)", "Transmission security. Implement technical security measures to guard against unauthorized access to data transmitted over a network."),
        ],
    )
}
fn ask(q: &str) -> (Verdict, String, Vec<String>) {
    let r = rt().search(q, Some("v"), 5, &Config::default());
    let ids = r.passages.iter().map(|p| p.clause_id.clone()).collect();
    (r.verdict, r.reason, ids)
}
fn abstains(q: &str) {
    let (v, why, ids) = ask(q);
    assert_eq!(v, Verdict::NotInCorpus, "{q} -> {ids:?} ({why})");
}
fn answers(q: &str, id: &str) {
    let (v, why, ids) = ask(q);
    assert_eq!(v, Verdict::Answered, "{q} ({why})");
    assert_eq!(ids[0], id, "{q}");
}

#[test]
fn h1_a_hipaa_section_or_lettered_subsection_that_is_not_held_abstains() {
    for q in [
        "What does 45 CFR 164.320(a) require?",
        "Explain HIPAA 164.312(f).",
        "What does 164.308(a)(1)(ii)(A) say about risk analysis?",
        "What does 164.404 require for notification of access control failures?",
        "164.312(a)(2)(iv) encryption and decryption access control",
    ] {
        abstains(q);
    }
}

#[test]
fn h2_hipaa_ids_that_exist_still_resolve_in_every_written_form() {
    answers("45 CFR \u{a7}164.312(e): explain.", "164.312(e)");
    answers("What is HIPAA 164.312 (a)?", "164.312(a)");
    answers("hipaa 164.312(A) access control", "164.312(a)");
    // a bare held section gives its subsections, and a bare section that is not held abstains
    let (v, _, ids) = ask("What does 164.312 cover?");
    assert_eq!(v, Verdict::Answered);
    assert!(ids.contains(&"164.312(a)".to_string()) && ids.contains(&"164.312(e)".to_string()));
    abstains("What does 164.316 cover?");
}

#[test]
fn h3_a_nonexistent_nested_or_family_id_abstains_even_when_its_parent_exists() {
    for q in [
        "What does PCI DSS requirement 8.3.6.2 say?",
        "Explain NIST SP 800-53 control AC-99.",
        "What does control ZZ-3 in the NIST catalog require?",
        "Summarise enhancement SC-7(6) of the NIST 800-53 catalog.",
        "What does AC-2(9) require?",
        "What does Article 150 of the EU AI Act require?",
        "Describe Annex XV of the AI Act.",
        "Describe Annex 9 of the AI Act.",
        "What does Article 43 of the DORA RTS require?",
    ] {
        abstains(q);
    }
}

#[test]
fn h4_existing_ids_in_all_the_held_forms_answer() {
    answers("What does AC-2 (4) require?", "AC-2(4)");
    answers("tell me about ac-2(4)", "AC-2(4)");
    answers("PCI DSS 4.0 requirement 8.3.6, what does it say?", "8.3.6");
    answers("Requirement 8.3.6 of PCI DSS v4.0.1 says what?", "8.3.6");
    answers("AI Act Annex III, what is in it?", "Annex III");
    answers("Summarise art. 12 of the AI Act.", "Art.12");
    answers("DORA RTS Article 9: what does it set out?", "Art.9");
}

#[test]
fn h5_version_and_product_numbers_and_other_standards_codes_are_not_clause_ids() {
    // 1.2 and 5.1 exist as PCI ids; here they are a protocol version and another standard's annex code
    abstains("Which TLS 1.2 cipher suites are acceptable for the audit service?");
    abstains("What does ISO 27001 annex A.5.1 require for malware protection?");
    abstains("What does SOC 2 criterion CC6.1 require for logical access?");
}
