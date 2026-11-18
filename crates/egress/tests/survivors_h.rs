//! EG1b mutation triage, batch H: what `scan` reports for coincident and adjacent matches. (1) two different detectors on the same span are two hits
//! (`dedupe` removes only identical detector-and-span pairs); two hits of one detector that end at the same place but start differently are two hits; (2) in one run of
//! digits and single separators only the first card is reported (documented: the first suffices to block); a comma and a space start a new run, so a second card is found.
//! Equivalent in practice (listed in a stage record (not published)): `dedupe` with `end !=` (it would need two hits of one detector with one start and different ends), and
//! the walker's separator tests that only change which neighbouring character is looked at without changing the digits walked.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::detect::scan;

fn hits(t: &str) -> Vec<(&'static str, usize, usize)> {
    let p = policy();
    scan(t, p.detect_cfg())
        .into_iter()
        .map(|h| (h.det.as_str(), h.start, h.end))
        .collect()
}

#[test]
fn h1_different_detectors_on_the_same_span_are_both_kept() {
    let t = "tok sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD end";
    assert_eq!(
        hits(t),
        vec![("D1", 4, 47), ("D6", 4, 47)],
        "a key format and the entropy record on one span"
    );
}

#[test]
fn h2_one_detector_with_two_spans_that_end_together_keeps_both() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijklmnop";
    let t = format!("send Authorization: Bearer {jwt} now");
    let h = hits(&t);
    let d3: Vec<_> = h.iter().filter(|x| x.0 == "D3").collect();
    let end = t.find(" now").unwrap();
    assert_eq!(
        d3.len(),
        3,
        "the header form, the bare Bearer rule and the JWT inside them, all ending together: {h:?}"
    );
    assert!(d3.iter().all(|x| x.2 == end), "{d3:?}");
    let mut starts: Vec<usize> = d3.iter().map(|x| x.1).collect();
    starts.sort_unstable();
    assert_eq!(starts, vec![5, 20, t.find("eyJ").unwrap()], "{d3:?}");
}

#[test]
fn h3_two_cards_in_one_run_of_digits_report_the_first_and_a_comma_starts_a_new_run() {
    let c = "4111111111111111";
    assert_eq!(
        hits(&format!("{c} {c}")),
        vec![("D4", 0, 16)],
        "one space: the same run"
    );
    assert_eq!(
        hits(&format!("{c}-{c}")),
        vec![("D4", 0, 16)],
        "one dash: the same run"
    );
    assert_eq!(
        hits(&format!("{c}, {c}")),
        vec![("D4", 0, 16), ("D4", 18, 34)],
        "a comma ends the run"
    );
    assert_eq!(
        hits(&format!("{c}  {c}")),
        vec![("D4", 0, 16), ("D4", 18, 34)],
        "two spaces end the run"
    );
    // a separator not followed by a digit is not part of the run: the number ends before it
    assert_eq!(hits(&format!("{c} x")), vec![("D4", 0, 16)]);
    assert_eq!(hits(&format!("x {c}")), vec![("D4", 2, 18)]);
}
