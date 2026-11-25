//! R2 tasks 2 to 4: the deterministic ranking, stuffing, length and abstention mechanisms. Each mechanism is tested with explicit
//! parameters (the knob works) so a later change of the tuned defaults cannot silently remove a mechanism.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{text_sha256, Clause, Tier};
use entropa_standards::retrieve::{Config, Retriever, Verdict};
use entropa_standards::text;

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
fn r(clauses: Vec<Clause>) -> Retriever {
    Retriever::from_clauses("v", &"0".repeat(64), clauses)
}
fn top(r: &Retriever, q: &str, cfg: &Config) -> String {
    let res = r.search(q, Some("v"), 3, cfg);
    match res.passages.first() {
        Some(p) if res.verdict == Verdict::Answered => format!("{}:{}", p.standard, p.clause_id),
        _ => format!("abstain:{}", res.reason),
    }
}
fn loose() -> Config {
    // every R2 mechanism neutral and every gate off: each test switches on only what it tests
    Config {
        unindexed_guard: false,
        score_floor: 0.0,
        coverage_min: 0.0,
        min_norm_score: 0.0,
        head_weight: 0.0,
        tf_cap: 100_000,
        len_cap_mult: 1e9,
        cov_exp: 0.0,
        prose_penalty: 1.0,
        phrase_weight: 0.0,
        parent_ratio: 0.0,
        head_only_factor: 1.0,
        entity_guard: false,
        // R3: the structural clause flags are tested in flags3.rs; here every mechanism is neutral
        structural_flags: false,
        ..Config::default()
    }
}
fn filler(n: usize) -> String {
    "The operator keeps general records about widget operations and supplier contacts. ".repeat(n)
}

// ---- task 2: ranking ----
#[test]
fn t2a_a_term_in_the_clause_head_outranks_the_same_term_only_in_a_short_body() {
    let long_title = format!("Key rotation. {}", filler(2));
    let short_body = "Staff review key rotation twice yearly.";
    let rt = r(vec![
        c("S", "S-1", &long_title),
        c("S", "S-2", short_body),
        c("S", "S-3", &filler(3)),
    ]);
    let off = loose();
    let on = Config {
        head_weight: 2.0,
        ..loose()
    };
    assert_eq!(top(&rt, "key rotation", &off), "S:S-2");
    assert_eq!(top(&rt, "key rotation", &on), "S:S-1");
}

#[test]
fn t2b_a_clause_covering_all_the_query_terms_beats_one_repeating_a_single_term() {
    let rt = r(vec![
        c(
            "S",
            "S-1",
            "Backup restore. Operators restore backups and record the restore time every quarter.",
        ),
        c(
            "S",
            "S-2",
            "Backup. Backup backup backup backup backup copies are kept.",
        ),
        c("S", "S-3", &filler(2)),
    ]);
    let cfg = Config {
        cov_exp: 1.0,
        tf_cap: 1000,
        ..loose()
    };
    assert_eq!(
        top(
            &rt,
            "how often are backups restored and the restore time recorded",
            &cfg
        ),
        "S:S-1"
    );
}

#[test]
fn t2c_adjacent_query_words_found_together_beat_the_same_words_scattered() {
    let rt = r(vec![
        c("S", "S-1", "Incident handling. Staff respond to each plan after a response drill and every incident report without delay."),
        c("S", "S-2", "Incident response. Staff keep a documented plan for each case without delay."),
        c("S", "S-3", &filler(2)),
    ]);
    let off = Config {
        phrase_weight: 0.0,
        head_weight: 0.0,
        ..loose()
    };
    let on = Config {
        phrase_weight: 2.0,
        head_weight: 0.0,
        ..loose()
    };
    let q = "incident response plan";
    assert_eq!(top(&rt, q, &off), "S:S-1");
    assert_eq!(top(&rt, q, &on), "S:S-2");
}

#[test]
fn t2d_a_clause_is_preferred_over_its_own_enhancement_when_their_scores_are_close() {
    let rt = r(vec![
        c("S", "AB-5", "Maintenance personnel. Authorise the people who perform maintenance and escort visitors."),
        c("S", "AB-5(5)", "Maintenance personnel escort. Authorise the people who perform maintenance and escort visitors and record each escort."),
        c("S", "AB-6", &filler(2)),
    ]);
    let off = Config {
        parent_ratio: 0.0,
        ..loose()
    };
    let on = Config {
        parent_ratio: 0.5,
        ..loose()
    };
    let q = "authorise maintenance people escort visitors record";
    assert_eq!(top(&rt, q, &off), "S:AB-5(5)");
    assert_eq!(top(&rt, q, &on), "S:AB-5");
}

// ---- task 3: stuffing and length ----
#[test]
fn t3a_repeating_a_term_a_hundred_times_does_not_beat_the_clause_that_answers() {
    let stuffed = "audit retention months ".repeat(100);
    let rt = r(vec![
        c(
            "S",
            "S-1",
            "Records. Operators keep each audit record under a retention rule of twelve months.",
        ),
        c("S", "S-2", &stuffed),
        c("S", "S-3", &filler(2)),
    ]);
    let q = "audit retention months";
    let uncapped = Config {
        len_cap_mult: 4.0,
        ..loose()
    };
    let capped = Config {
        tf_cap: 3,
        len_cap_mult: 4.0,
        ..loose()
    };
    assert_eq!(top(&rt, q, &uncapped), "S:S-2");
    assert_eq!(top(&rt, q, &capped), "S:S-1");
}

#[test]
fn t3b_one_huge_clause_in_one_standard_does_not_change_scores_in_another_standard() {
    let base = vec![
        c(
            "Y",
            "Y-1",
            "Visitor control. Visitors wear a badge and are escorted at all times.",
        ),
        c(
            "Y",
            "Y-2",
            "Reporting. Incidents are reported in three days.",
        ),
        c("X", "X-1", "Scope. This applies to widgets."),
        c("X", "X-2", "Definitions. A widget is a device."),
    ];
    let mut with_normal = base.clone();
    with_normal.push(c("X", "X-3", "Notes. Widgets are kept in racks."));
    let mut with_huge = base;
    with_huge.push(c("X", "X-3", &filler(3000)));
    let cfg = loose();
    let q = "visitors badge escorted";
    let s = |rt: &Retriever| {
        rt.search(
            q,
            Some("v"),
            1,
            &Config {
                scope_by_standard_name: false,
                ..cfg.clone()
            },
        )
        .passages
        .iter()
        .find(|p| p.standard == "Y")
        .map(|p| p.score)
    };
    let (a, b) = (s(&r(with_normal)), s(&r(with_huge)));
    assert!(a.is_some());
    assert_eq!(a, b);
}

#[test]
fn t3c_a_keyword_block_without_prose_ranks_below_the_sentence_that_answers() {
    let rt = r(vec![
        c("S", "S-1", "Visitor control. Visitors shall be signed in at reception, wear a badge and be escorted at all times inside the secure area."),
        c("S", "S-2", "visitors reception badge escorted secure area signed escort badge visitors area reception inside times"),
        c("S", "S-3", &filler(2)),
    ]);
    let q = "what must happen to visitors entering the secure area";
    assert_eq!(top(&rt, q, &loose()), "S:S-2");
    let on = Config {
        prose_penalty: 0.6,
        ..loose()
    };
    assert_eq!(top(&rt, q, &on), "S:S-1");
}

#[test]
fn t3f_a_heading_that_copies_the_question_but_has_no_body_behind_it_does_not_win() {
    let rt = r(vec![
        c("S", "S-1", "Retention. Operators retain audit logs for twelve months and keep the latest three months online for analysis."),
        c("S", "S-2", "How long must audit logs be retained and how many months stay online for analysis. Contact the registry for pricing."),
        c("S", "S-3", &filler(2)),
    ]);
    let q = "how long must audit logs be retained and how many months stay online for analysis";
    let off = Config {
        head_only_factor: 1.0,
        ..loose()
    };
    let on = Config {
        head_only_factor: 0.1,
        ..loose()
    };
    assert_eq!(top(&rt, q, &off), "S:S-2");
    assert_eq!(top(&rt, q, &on), "S:S-1");
}

#[test]
fn t3d_zero_width_characters_do_not_split_words() {
    assert_eq!(
        text::tokens("au\u{200b}dit lo\u{feff}gs"),
        vec!["audit", "log"]
    );
}

#[test]
fn t3e_a_single_letter_clause_id_is_an_id() {
    let rt = r(vec![
        c("SYN", "Z-1", "Definitions. A widget is a device."),
        c(
            "SYN",
            "Z-2",
            "Log retention. Operators retain audit logs twelve months.",
        ),
    ]);
    let res = rt.search(
        "what does clause Z-2 require",
        Some("v"),
        3,
        &Config::default(),
    );
    assert_eq!(res.reason, "exact_id");
    assert_eq!(res.passages[0].clause_id, "Z-2");
}

// ---- task 4: abstention without a name list ----
#[test]
fn t4a_the_shipped_configuration_has_no_name_list() {
    assert!(!Config::default().unindexed_guard);
}

#[test]
fn t4b_the_shipped_gate_answers_on_a_tiny_corpus() {
    let rt = r(vec![
        c("SYN", "Z-1", "Definitions. A widget is a device."),
        c(
            "SYN",
            "Z-2",
            "Log retention. Operators retain audit logs for twelve months.",
        ),
        c("SYN", "Z-3", "Scope. This applies to widgets."),
        c(
            "SYN",
            "Z-4",
            "Reporting. Incidents are reported in three days.",
        ),
    ]);
    assert_eq!(
        top(&rt, "how long are audit logs retained", &Config::default()),
        "SYN:Z-2"
    );
}

#[test]
fn t4c_an_unknown_acronym_not_in_the_corpus_vocabulary_abstains_without_any_list() {
    let rt = r(vec![
        c("S", "S-1", "Consent. Individuals shall consent to the processing of personal data before collection."),
        c("S", "S-2", "Notice. Individuals shall be told how personal data is processed."),
        c("S", "S-3", &filler(2)),
    ]);
    let cfg = Config {
        coverage_min: 0.5,
        min_norm_score: 0.0,
        ..Config::default()
    };
    assert_eq!(
        top(
            &rt,
            "what does consent processing of personal data require",
            &cfg
        ),
        "S:S-1"
    );
    assert!(top(
        &rt,
        "what does PIPEDA say about consent and personal data",
        &cfg
    )
    .starts_with("abstain"));
    // RS1: `foreign_any_name` (ON since the RS1 freeze) is a second guard on unknown ALL-CAPS names; it is switched off here so that this test still isolates `entity_guard`
    let no_guard = Config {
        entity_guard: false,
        foreign_any_name: false,
        ..cfg
    };
    assert_eq!(
        top(
            &rt,
            "what does PIPEDA say about consent and personal data",
            &no_guard
        ),
        "S:S-1"
    );
}

#[test]
fn t4d_an_id_shaped_token_that_does_not_exist_still_abstains() {
    let rt = r(vec![
        c("S", "AC-1", "Policy. Access control policy shall exist."),
        c("S", "AC-2", "Accounts. Accounts are managed."),
    ]);
    assert_eq!(
        top(&rt, "what does AC-99 require", &Config::default()),
        "abstain:id_not_in_corpus"
    );
}

#[test]
fn t4e_an_off_topic_question_abstains_on_the_relative_gate_alone() {
    let rt = r(vec![
        c(
            "S",
            "S-1",
            "Audit logs. Operators retain audit logs for twelve months.",
        ),
        c(
            "S",
            "S-2",
            "Backups. Operators restore backups every quarter.",
        ),
        c("S", "S-3", "Visitors. Visitors wear a badge."),
    ]);
    let cfg = Config {
        entity_guard: false,
        ..Config::default()
    };
    assert!(top(
        &rt,
        "how do I bake sourdough bread with a long fermentation",
        &cfg
    )
    .starts_with("abstain"));
}
