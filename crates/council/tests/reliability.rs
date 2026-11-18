//! Critic-reliability scoring: (accepted_weight + 1) / (accepted_weight + rejected_weight + 2), severity weighted.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use proptest::prelude::*;

const R: &str = "gemini-flash";
const C: &str = "missing_approval";

fn loaded() -> Reliability {
    let mut r = Reliability::new(1_000_000);
    for t in 0..3 {
        r.record(R, C, "high", Verdict::Accepted, 100 + t);
    }
    r.record(R, C, "low", Verdict::Rejected, 200);
    r
}

#[test]
fn r1_the_score_is_the_smoothed_weighted_acceptance_rate() {
    let s = loaded().score(R, C, 300);
    assert_eq!((s.accepted_weight, s.rejected_weight, s.decided), (9, 1, 4));
    assert_eq!(s.permille, 833, "floor(1000 x (9 + 1) / (9 + 1 + 2))");
}

#[test]
fn r2_deferred_findings_are_ignored() {
    let mut r = loaded();
    r.record(R, C, "hard_rule", Verdict::Deferred, 250);
    let s = r.score(R, C, 300);
    assert_eq!(
        (s.accepted_weight, s.rejected_weight, s.decided, s.permille),
        (9, 1, 4, 833)
    );
}

#[test]
fn r3_severity_weights_are_one_two_three_four() {
    let mut r = Reliability::new(1_000_000);
    for (i, sev) in ["low", "medium", "high", "hard_rule"].iter().enumerate() {
        r.record(R, C, sev, Verdict::Accepted, 10 + i as u64);
    }
    let s = r.score(R, C, 100);
    assert_eq!(s.accepted_weight, 10);
    assert_eq!(s.permille, 916, "floor(1000 x 11 / 12)");
    let mut r = Reliability::new(1_000_000);
    for (i, sev) in ["low", "medium", "high", "hard_rule"].iter().enumerate() {
        r.record(R, C, sev, Verdict::Rejected, 10 + i as u64);
    }
    let s = r.score(R, C, 100);
    assert_eq!(
        (s.rejected_weight, s.permille),
        (10, 83),
        "floor(1000 x 1 / 12)"
    );
}

#[test]
fn r4_no_data_is_one_half() {
    let s = Reliability::new(100).score("nobody", "nothing", 1000);
    assert_eq!(
        (s.accepted_weight, s.rejected_weight, s.decided, s.permille),
        (0, 0, 0, 500)
    );
}

#[test]
fn r5_only_decisions_inside_the_rolling_window_count() {
    let mut r = Reliability::new(100);
    r.record(R, C, "high", Verdict::Accepted, 1000);
    assert_eq!(r.score(R, C, 1099).decided, 1, "99 seconds old: inside");
    assert_eq!(r.score(R, C, 1100).decided, 0, "100 seconds old: outside");
    assert_eq!(r.score(R, C, 1100).permille, 500);
}

#[test]
fn r6_scores_are_kept_per_reviewer_and_per_class() {
    let r = loaded();
    assert_eq!(r.score(R, "wrong_subject", 300).decided, 0);
    assert_eq!(r.score("nova-lite", C, 300).decided, 0);
    assert_eq!(r.score(R, C, 300).decided, 4);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn r7_more_acceptance_never_lowers_the_score_and_it_stays_in_range(a in 0u64..30, rej in 0u64..30, extra in 1u64..10) {
        let build = |acc: u64| {
            let mut r = Reliability::new(u64::MAX / 2);
            for i in 0..acc { r.record(R, C, "medium", Verdict::Accepted, i); }
            for i in 0..rej { r.record(R, C, "medium", Verdict::Rejected, 1000 + i); }
            r.score(R, C, 5000).permille
        };
        let (before, after) = (build(a), build(a + extra));
        prop_assert!(after >= before && before <= 1000 && after <= 1000);
    }
}
