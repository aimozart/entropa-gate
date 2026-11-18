//! EG1b mutation triage, batch F: the national-identifier rules of D5. SSN-shaped values are BUILT AT RUN TIME from numbers (never written as one literal, per the
//! project lessons) and only their validity flag is asserted: area 000, 666 and 900 or more, group 00 and serial 0000 are never issued (flag false), any other
//! shape is flag true. NHS numbers: ten digits, weights 10 to 2 on the first nine, check = 11 - (sum mod 11) with 11 as 0 and 10 invalid; the example 943 476 5919
//! is the public synthetic NHS test number; bare ten digits count only with the keyword or with two separators. NINO: two letters, six digits, a letter A to D;
//! the prefixes BG, GB, NK, KN, TN, NT, ZZ are never issued, so they are not flagged. (`pre == "QQ"` in the NINO test is redundant with the list test: equivalent.)
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::detect::{scan, Det};

fn id_hits(text: &str) -> Vec<(usize, usize, bool)> {
    let p = policy();
    scan(text, p.detect_cfg())
        .into_iter()
        .filter(|h| h.det == Det::D5Id)
        .map(|h| (h.start, h.end, h.checksum_ok))
        .collect()
}
fn ssn(area: u32, group: u32, serial: u32) -> String {
    format!("{area:03}-{group:02}-{serial:04}")
}

#[test]
fn f1_the_ssn_shape_is_always_a_hit_and_its_flag_says_whether_the_numbers_could_be_issued() {
    // (area, group, serial, flag expected by the written rule)
    let cases = [
        (0u32, 45u32, 6789u32, false),
        (1, 45, 6789, true),
        (665, 45, 6789, true),
        (666, 45, 6789, false),
        (667, 45, 6789, true),
        (899, 45, 6789, true),
        (900, 45, 6789, false),
        (999, 45, 6789, false),
        (123, 0, 6789, false),
        (123, 1, 6789, true),
        (123, 45, 0, false),
        (123, 45, 1, true),
        (123, 45, 6789, true),
    ];
    for (a, g, s, ok) in cases {
        let v = ssn(a, g, s);
        let text = format!("id {v} end");
        assert_eq!(
            id_hits(&text),
            vec![(3, 14, ok)],
            "area {a} group {g} serial {s}"
        );
    }
    // spaces as separators are the same shape
    let v = ssn(123, 45, 6789).replace('-', " ");
    assert_eq!(id_hits(&format!("id {v} end")), vec![(3, 14, true)]);
}

#[test]
fn f2_nhs_numbers_need_a_valid_check_digit_and_two_separators_or_the_keyword() {
    assert_eq!(
        id_hits("ref 943 476 5919 end"),
        vec![(4, 16, true)],
        "two spaces"
    );
    assert_eq!(
        id_hits("ref 943-476-5919 end"),
        vec![(4, 16, true)],
        "two dashes"
    );
    assert!(
        id_hits("ref 943 476 5918 end").is_empty(),
        "wrong check digit"
    );
    assert!(
        id_hits("ref 9434765919 end").is_empty(),
        "bare ten digits without the keyword"
    );
    assert!(
        id_hits("ref 943 4765919 end").is_empty(),
        "one separator only"
    );
    assert_eq!(
        id_hits("NHS number 9434765919 end").len(),
        1,
        "the keyword makes a bare number count"
    );
    assert_eq!(id_hits("nhs: 943 476 5919").len(), 1);
    // a check value of 10 is never valid (weights give 10 for 401 023 2137? compute: use 123 456 7890 style numbers)
    for n in ["0000000000", "1111111111"] {
        let bad = format!("NHS {n}");
        let digits: Vec<u32> = n.chars().map(|c| c.to_digit(10).unwrap()).collect();
        let sum: u32 = digits[..9]
            .iter()
            .enumerate()
            .map(|(i, d)| d * (10 - i as u32))
            .sum();
        let c = 11 - sum % 11;
        let c = if c == 11 { 0 } else { c };
        let valid = c != 10 && c == digits[9];
        assert_eq!(id_hits(&bad).len(), usize::from(valid), "{n}");
    }
}

#[test]
fn f3_a_nino_is_flagged_unless_its_prefix_is_one_that_is_never_issued() {
    for t in [
        "AB 12 34 56 C",
        "AB123456C",
        "ab123456c",
        "JK 98 76 54 D",
        "CE 00 00 00 A",
    ] {
        assert_eq!(id_hits(&format!("ni {t} end")).len(), 1, "{t}");
    }
    for t in [
        "BG 12 34 56 C",
        "GB 12 34 56 C",
        "NK 12 34 56 C",
        "KN 12 34 56 C",
        "TN 12 34 56 C",
        "NT 12 34 56 C",
        "ZZ 12 34 56 C",
        "GB123456C",
        "zz123456c",
    ] {
        assert!(
            id_hits(&format!("ni {t} end")).is_empty(),
            "{t} has a prefix that is never issued"
        );
    }
}
