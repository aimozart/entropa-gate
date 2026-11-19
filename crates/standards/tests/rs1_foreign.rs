//! RS1 candidate 3 (a stage record (not published)): an unknown ALL-CAPS name anywhere in the question (CCPA, FedRAMP-style acronyms) means the question is about a standard this corpus does not hold,
//! with no list of names and no need for a following word like "Act". Switch `foreign_any_name=1`, OFF by default. Synthetic corpus only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{Clause, Tier};
use entropa_standards::r2eval::apply_overrides;
use entropa_standards::retrieve::{Config, Retriever, Verdict};

fn clause(std: &str, id: &str, text: &str) -> Clause {
    Clause {
        standard: std.into(),
        std_version: "1".into(),
        id: id.into(),
        tier: Tier::Open,
        text: text.into(),
        text_sha256: entropa_standards::corpus::text_sha256(text),
    }
}
fn r() -> Retriever {
    Retriever::from_clauses(
        "v1",
        &"1".repeat(64),
        vec![
            clause("SYN", "A-1", "The operator shall encrypt stored backups and keep the keys apart from the backups, as the BRAVO scheme requires."),
            clause("SYN", "A-2", "The operator shall review access rights for every account once a year and remove rights that are no longer needed."),
            clause("SYN", "A-3", "Visitors shall sign the register at the front desk and wear a badge in the building at all times."),
        ],
    )
}
fn on() -> Config {
    let mut c = Config::default();
    apply_overrides(&mut c, "foreign_any_name=1").unwrap();
    c
}
fn off() -> Config {
    let mut c = Config::default();
    apply_overrides(&mut c, "foreign_any_name=0").unwrap();
    c
}

#[test]
fn f1_on_by_default_since_the_rs1_freeze_and_switchable() {
    assert!(Config::default().foreign_any_name);
    assert!(on().foreign_any_name);
    assert!(!off().foreign_any_name);
}

#[test]
fn f2_an_unknown_all_caps_name_makes_the_question_abstain_when_the_switch_is_on() {
    let q = "What does the QUEBEC say about encrypting stored backups?";
    let q2 = "What does QUEBEC say about reviewing access rights every year?";
    for q in [q, q2] {
        let off = r().search(q, None, 3, &off());
        assert_eq!(
            off.verdict,
            Verdict::Answered,
            "{q}: baseline answers from shared words"
        );
        let res = r().search(q, None, 3, &on());
        assert_eq!(res.verdict, Verdict::NotInCorpus, "{q}");
        assert_eq!(res.reason, "other_standard");
    }
}

#[test]
fn f3_a_name_the_corpus_holds_does_not_abstain_and_plain_questions_are_unchanged() {
    let held = r().search(
        "What does the BRAVO scheme say about encrypting stored backups?",
        None,
        3,
        &on(),
    );
    assert_eq!(
        held.verdict,
        Verdict::Answered,
        "BRAVO is in the corpus text"
    );
    let plain = r().search(
        "How often must access rights be reviewed for every account?",
        None,
        3,
        &on(),
    );
    assert_eq!(plain.verdict, Verdict::Answered);
    assert_eq!(plain.passages[0].clause_id, "A-2");
    // a clause id and a two-letter word are not names
    let id = r().search(
        "What does A-2 say about reviewing access rights?",
        None,
        3,
        &on(),
    );
    assert_eq!(id.verdict, Verdict::Answered);
    let two = r().search(
        "Does AI review access rights for every account?",
        None,
        3,
        &on(),
    );
    assert_ne!(two.reason, "other_standard");
}
