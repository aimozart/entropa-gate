//! EG1c mutation triage (tests only): survivors of the first cargo-mutants run on `views::leaf_candidates`, observed through the public `views::decoded`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::views::decoded;

fn chain_count(raw: &str, name: &str) -> usize {
    decoded(raw)
        .iter()
        .filter(|d| d.chain.first() == Some(&name))
        .count()
}

#[test]
fn k1_a_single_line_text_gets_one_whole_text_candidate_not_two() {
    // one line with spaces: the whole text is the leaf; the line must not be added a second time
    let raw = "alpha beta gamma delta epsilon";
    assert_eq!(chain_count(raw, "rot13"), 1, "rot13");
    assert_eq!(chain_count(raw, "reverse"), 1, "reverse");
}

#[test]
fn k2_a_line_shorter_than_twelve_characters_is_not_a_leaf() {
    // two lines: the first has 11 characters with a regular hyphen grouping (g=3 removes positions 4 and 8)
    let raw = "abc-def-ghi\nplain second line of words";
    assert_eq!(chain_count(raw, "hyphen"), 0, "11 characters: not a leaf");
    let raw12 = "abc-def-ghi-\nplain second line of words";
    assert_eq!(chain_count(raw12, "hyphen"), 1, "12 characters: a leaf");
}

#[test]
fn k3_the_line_cap_is_4096_characters_and_does_not_apply_to_the_whole_text_for_rot13() {
    let line = |extra: &str| format!("{}{extra}", "ab ".repeat(1365)); // 4,095 characters plus extra
                                                                       // a line of exactly 4,096 characters is a leaf; one of 4,097 is not
    let at_cap = format!("{}\nshort tail words", line("x"));
    let over = format!("{}\nshort tail words", line("xy"));
    assert_eq!(at_cap.lines().next().unwrap().len(), 4096);
    assert_eq!(
        chain_count(&at_cap, "rot13"),
        3,
        "whole text, the 4,096-character line and the tail"
    );
    assert_eq!(
        chain_count(&over, "rot13"),
        2,
        "whole text and the tail only: the long line is skipped"
    );
}

#[test]
fn k4_no_hyphen_candidate_is_made_from_a_leaf_longer_than_the_cap() {
    let long = format!("{}\nx", "abc-".repeat(1100)); // 4,400 characters, regular hyphens at g=3
    assert_eq!(chain_count(&long, "hyphen"), 0);
    let short = format!("{}\nx", "abc-".repeat(100));
    assert!(chain_count(&short, "hyphen") >= 1);
}

#[test]
fn k5_the_expansion_budget_is_charged_and_never_exceeded() {
    // 300 lines of 40 hyphens: every line gives six hyphen candidates (all g are regular), far more than four times the input
    let raw = format!("{}\n", "-".repeat(40)).repeat(300);
    let total: usize = decoded(&raw).iter().map(|d| d.text.len()).sum();
    assert!(
        total <= raw.len() * 4 + 1024,
        "{total} bytes of candidates for {} bytes of input",
        raw.len()
    );
}
