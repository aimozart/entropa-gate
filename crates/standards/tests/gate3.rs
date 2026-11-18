//! R3 task 2: the abstention gate counts CONTENT words (function words excluded, stems on): one shared word never suffices, a minimum number of
//! distinct content words must match the top clause, and a coverage floor over the query's own content words must be met. No name list.
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
            c("S", "A-1", "Backup. Conduct backups of the home directory and keep the configuration in the image built each week."),
            c("S", "A-2", "Penetration testing. A red team simulates attacks across the world of systems in a series of exercises and reports weaknesses."),
            c("S", "A-3", "Password rules. Passwords for routers and other network devices shall be changed before the devices are put into service."),
            c("S", "A-4", "Audit log retention. The operator shall keep audit logs for twelve months and hold the latest three months online."),
            c("S", "A-5", "Screen lock. Workstations lock after five minutes without input and need the password to unlock."),
        ],
    )
}
fn ask(q: &str) -> (Verdict, String) {
    let r = rt().search(q, Some("v"), 3, &Config::default());
    (r.verdict, r.reason)
}

#[test]
fn g1_one_shared_content_word_never_suffices() {
    for q in [
        "What is a good recipe for sourdough bread with a crispy crust and a home baked flavour?",
        "Which team won the baseball game against the rivals last night?",
        "Where can I buy cheap garden furniture for the summer season?",
    ] {
        let (v, why) = ask(q);
        assert_eq!(v, Verdict::NotInCorpus, "{q} ({why})");
    }
}

#[test]
fn g2_two_shared_words_with_a_low_share_of_the_questions_own_content_words_abstain() {
    for q in [
        "How do I choose a strong password for my home wifi router so the neighbours cannot use it?",
        "Which team won the baseball world series in 2019 and who was the best pitcher?",
        "What does the new firmware update change about my laptop battery life and screen brightness?",
    ] {
        let (v, why) = ask(q);
        assert_eq!(v, Verdict::NotInCorpus, "{q} ({why})");
    }
}

#[test]
fn g3_a_real_paraphrase_that_shares_most_of_its_content_words_still_answers() {
    let r = rt().search(
        "How long must the audit logs be kept, and how many months stay online?",
        Some("v"),
        3,
        &Config::default(),
    );
    assert_eq!(r.verdict, Verdict::Answered, "{}", r.reason);
    assert_eq!(r.passages[0].clause_id, "A-4");
    let r = rt().search(
        "After how many minutes does a workstation lock and need a password?",
        Some("v"),
        3,
        &Config::default(),
    );
    assert_eq!(r.verdict, Verdict::Answered, "{}", r.reason);
    assert_eq!(r.passages[0].clause_id, "A-5");
}

#[test]
fn g4_no_content_word_in_the_corpus_vocabulary_abstains_whatever_the_other_switches() {
    let cfg = Config {
        entity_guard: false,
        foreign_guard: false,
        min_norm_score: 0.0,
        coverage_min: 0.0,
        ..Config::default()
    };
    let r = rt().search(
        "Which volcano erupted in Iceland and closed the airports?",
        Some("v"),
        3,
        &cfg,
    );
    assert_eq!(r.verdict, Verdict::NotInCorpus);
    assert!(
        r.reason == "no_content_word" || r.reason == "below_gate",
        "{}",
        r.reason
    );
}

#[test]
fn g5_the_name_list_makes_no_difference_to_everyday_questions() {
    for list in [false, true] {
        let cfg = Config {
            unindexed_guard: list,
            ..Config::default()
        };
        let r = rt().search(
            "What is the best way to bake a cake at home for a birthday party?",
            Some("v"),
            3,
            &cfg,
        );
        assert_eq!(r.verdict, Verdict::NotInCorpus, "list={list}");
    }
}

#[test]
fn g6_the_gate_reports_why_it_abstained() {
    // the older gates are switched off so that the content-word gate is the one that speaks
    let cfg = Config {
        min_norm_score: 0.0,
        coverage_min: 0.0,
        entity_guard: false,
        foreign_guard: false,
        ..Config::default()
    };
    let r = rt().search(
        "What is the best way to bake a cake at home for a birthday party?",
        Some("v"),
        3,
        &cfg,
    );
    assert_eq!(r.verdict, Verdict::NotInCorpus);
    assert!(
        [
            "too_few_content_words",
            "low_content_coverage",
            "no_content_word"
        ]
        .contains(&r.reason.as_str()),
        "{}",
        r.reason
    );
}
