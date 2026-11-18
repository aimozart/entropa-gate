//! EG1b mutation triage, batch E: `run_stripped_rest` (the card-digit walker, do-not-send terms D7, markers D8) and `text_is_stripped`. Expected spans and counts are
//! written by hand from the documented rule (13 to 19 digits with single spaces or dashes between digit groups, a valid check digit, a known issuer range, and
//! no digit directly after; terms and markers of 8 or more characters are also searched as a substring in a stripped text; shorter ones only as whole words).
//! Equivalent mutants (argued in a stage record (not published)): `digits.len() < 19` to `<= 19` (a 20-digit candidate is never an issuer-range number, and the 19-digit
//! one is refused because a digit follows), and `j + 1` to `j - 1` in the separator test (it changes only which neighbour is looked at while the digit
//! run being walked is the same). Synthetic values only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use entropa_egress::detect::{scan, scan_kind, Det, ViewKind};
use entropa_egress::eval::{load_policy, policy_from_extra};
use serde_json::json;
use sha2::{Digest, Sha256};

fn luhn_digit(body: &str) -> char {
    let mut sum = 0u32;
    for (i, c) in body.chars().rev().enumerate() {
        let mut v = c.to_digit(10).unwrap();
        if i % 2 == 0 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    char::from_digit((10 - sum % 10) % 10, 10).unwrap()
}
fn visa(len: usize) -> String {
    let mut b = String::from("4");
    let mut k = 3u32;
    while b.len() < len - 1 {
        b.push(char::from_digit(k % 10, 10).unwrap());
        k = (k * 7 + 1) % 1000;
    }
    b.push(luhn_digit(&b));
    b
}
fn cfg_policy(extra: serde_json::Value) -> entropa_egress::policy::Policy {
    load_policy(&policy_from_extra(&extra)).unwrap()
}
fn d4(text: &str) -> Vec<(usize, usize)> {
    let p = cfg_policy(json!({}));
    scan(text, p.detect_cfg())
        .into_iter()
        .filter(|h| h.det == Det::D4)
        .map(|h| (h.start, h.end))
        .collect()
}

#[test]
fn e1_a_card_is_found_with_its_exact_span_in_every_grouping() {
    let n = visa(16);
    let (a, b, c, d) = (&n[0..4], &n[4..8], &n[8..12], &n[12..16]);
    for (text, start, end) in [
        (format!("pay {n} now"), 4, 20),
        (format!("pay {a} {b} {c} {d} now"), 4, 23),
        (format!("pay {a}-{b}-{c}-{d} now"), 4, 23),
        (n.to_string(), 0, 16),
        (format!("{a} {b}-{c} {d}"), 0, 19),
    ] {
        assert_eq!(d4(&text), vec![(start, end)], "{text}");
    }
    // 13 and 19 digits
    for len in [13usize, 19] {
        let m = visa(len);
        assert_eq!(d4(&format!("x {m} y")), vec![(2, 2 + len)], "{len} digits");
    }
}

#[test]
fn e2_digits_around_the_number_and_separators_at_the_edges_do_not_confuse_the_walker() {
    let n = visa(16);
    // a digit glued before or after the number: it is a longer number, not a card
    assert!(d4(&format!("1{n}")).is_empty(), "a digit before");
    assert!(d4(&format!("{n}7")).is_empty(), "a digit after");
    // 20 digits: no issuer range of 20, and the 19-digit prefix has a digit after it
    assert!(d4(&format!("{}{}", visa(19), "5")).is_empty());
    // a separator at the very end of the text, or a double separator: the span ends at the last digit and nothing panics
    assert_eq!(d4(&format!("{n}-")), vec![(0, 16)]);
    assert_eq!(d4(&format!("{n} ")), vec![(0, 16)]);
    assert_eq!(d4(&format!("{n}  x")), vec![(0, 16)]);
    // 12 digits (one short of the minimum) with a valid check digit is not a card, even grouped
    let mut short = String::from("4");
    while short.len() < 11 {
        short.push('3');
    }
    short.push(luhn_digit(&short));
    assert_eq!(short.len(), 12);
    assert!(d4(&short).is_empty());
    // two numbers apart: both are looked at, the first one is found
    assert_eq!(d4(&format!("a {n}, b")), vec![(2, 18)]);
}

#[test]
fn e3_terms_are_found_as_whole_words_and_as_substrings_only_from_eight_characters() {
    let p = cfg_policy(json!({"terms": ["Project Falcon9", "Falcon"]}));
    let hits = |t: &str, kind: ViewKind| -> Vec<(usize, usize)> {
        scan_kind(t, kind, p.detect_cfg())
            .into_iter()
            .filter(|h| h.det == Det::D7)
            .map(|h| (h.start, h.end))
            .collect()
    };
    // plain text: whole-word regex, exact span of the first matching word group
    assert_eq!(
        hits("about Project Falcon9 here", ViewKind::Raw),
        vec![(6, 21)],
        "the long term"
    );
    assert_eq!(
        hits("a Falcon flew", ViewKind::Raw),
        vec![(2, 8)],
        "the short term as a whole word"
    );
    assert!(
        hits("a Falconer flew", ViewKind::Raw).is_empty(),
        "not a whole word"
    );
    // a lower-case text with no separators is a stripped text: substring search for a needle of 8 or more characters
    assert_eq!(
        hits("xprojectfalcon9x", ViewKind::Stripped),
        vec![(1, 15)],
        "stripped: the long term is found inside other letters"
    );
    assert!(
        hits("xfalconx", ViewKind::Stripped).is_empty(),
        "stripped: 6 characters is too short to search as a substring"
    );
    // the same letters with an upper-case letter are not a stripped text: whole-word rules apply and 'x...x' glued letters do not match
    assert!(hits("xProjectFalcon9x", ViewKind::Raw).is_empty());
    // a text with a separator is not a stripped text either
    assert!(hits("xproject-falcon9x", ViewKind::Raw).is_empty());
    // an empty text finds nothing and does not panic
    assert!(hits("", ViewKind::Stripped).is_empty());
}

#[test]
fn e4_markers_are_found_like_terms_and_the_keyed_marker_checks_its_hash() {
    let key = "k-eg1b-test-key";
    let p = cfg_policy(json!({"markers": ["internal only label"], "marker_key": key}));
    let d8 = |t: &str, kind: ViewKind| -> Vec<(usize, usize, bool)> {
        scan_kind(t, kind, p.detect_cfg())
            .into_iter()
            .filter(|h| h.det == Det::D8)
            .map(|h| (h.start, h.end, h.checksum_ok))
            .collect()
    };
    assert_eq!(
        d8("see internal only label ok", ViewKind::Raw),
        vec![(4, 23, false)]
    );
    assert_eq!(
        d8("xinternalonlylabelx", ViewKind::Stripped),
        vec![(1, 18, false)]
    );
    assert!(
        d8("see internal only labels ok", ViewKind::Raw).is_empty(),
        "whole words"
    );
    // the keyed marker: EGM-<8 hex>-<first 8 hex of sha256(key + lower-case first part)>
    let a = "0a1b2c3d";
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    h.update(a.as_bytes());
    let good = hex::encode(h.finalize())[..8].to_string();
    let text = format!("copy EGM-{a}-{good} here");
    assert_eq!(
        d8(&text, ViewKind::Raw),
        vec![(5, 5 + 4 + 8 + 1 + 8, true)],
        "{text}"
    );
    let bad = format!(
        "copy EGM-{a}-{} here",
        if good.starts_with('0') { "1" } else { "0" }.to_string() + &good[1..]
    );
    assert!(
        d8(&bad, ViewKind::Raw).is_empty(),
        "a wrong hash is not a marker: {bad}"
    );
    // upper-case in the first part is lower-cased before hashing
    let up = format!("copy EGM-{}-{good} here", a.to_uppercase());
    assert_eq!(d8(&up, ViewKind::Raw).len(), 1, "{up}");
}

#[test]
fn e5_two_views_of_the_same_match_become_one_hit() {
    // the same key matched by the raw and the folded scan of one text is reported once with its span (dedupe by detector and span)
    let p = cfg_policy(json!({}));
    let hits: Vec<_> = scan("key AKIAIOSFODNN7EXAMPLE end", p.detect_cfg())
        .into_iter()
        .filter(|h| h.det == Det::D1)
        .collect();
    assert_eq!(hits.len(), 1, "{hits:?}");
    // two different keys are two hits, and the same key twice at two places is two hits
    let two: Vec<_> = scan(
        "AKIAIOSFODNN7EXAMPLE and ASIAIOSFODNN7EXAMPLE",
        p.detect_cfg(),
    )
    .into_iter()
    .filter(|h| h.det == Det::D1)
    .collect();
    assert_eq!(two.len(), 2);
    let again: Vec<_> = scan(
        "AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE",
        p.detect_cfg(),
    )
    .into_iter()
    .filter(|h| h.det == Det::D1)
    .collect();
    assert_eq!(again.len(), 2, "same text at two spans");
}
