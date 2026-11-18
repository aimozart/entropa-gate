//! EG1b mutation triage, batch D: the card issuer ranges and the placeholder rules. Card numbers are built here with an independent Luhn routine
//! (check digit from the body), by brand, prefix and length, so every range boundary of the written rule is exercised: Visa 4 at 13, 16, 19; Mastercard
//! 51-55 and 2221-2720 at 16; Amex 34, 37 at 15; Discover 6011, 65, 644-649 at 16-19; JCB 3528-3589 at 16-19; Diners 300-305, 36, 38 at 14-19; UnionPay 62 at 16-19.
//! A number with a valid check digit but a prefix or length outside these is NOT a card. Synthetic digits only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::detect::{scan, Det};

fn luhn_check_digit(body: &str) -> char {
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
/// A number of `len` digits starting with `prefix`, filled by a counter, with a valid check digit.
fn card(prefix: &str, len: usize, salt: u32) -> String {
    let mut body = prefix.to_string();
    let mut k = salt;
    while body.len() < len - 1 {
        body.push(char::from_digit((k * 7 + 3) % 10, 10).unwrap());
        k += 1;
    }
    let c = luhn_check_digit(&body);
    body.push(c);
    body
}
fn is_card(n: &str) -> bool {
    let p = policy();
    scan(&format!("number {n} end"), p.detect_cfg())
        .iter()
        .any(|h| h.det == Det::D4)
}

#[test]
fn d1_every_listed_issuer_range_and_length_is_a_card() {
    let mut cases: Vec<(String, usize)> = vec![];
    for len in [13, 16, 19] {
        cases.push(("4".into(), len));
    }
    for p in ["51", "52", "53", "54", "55", "2221", "2500", "2720"] {
        cases.push((p.into(), 16));
    }
    for p in ["34", "37"] {
        cases.push((p.into(), 15));
    }
    for len in 16..=19 {
        for p in [
            "6011", "65", "644", "647", "649", "3528", "3560", "3589", "62",
        ] {
            cases.push((p.into(), len));
        }
    }
    for len in 14..=19 {
        for p in ["300", "303", "305", "36", "38"] {
            cases.push((p.into(), len));
        }
    }
    for (i, (p, len)) in cases.iter().enumerate() {
        let n = card(p, *len, i as u32);
        assert_eq!(n.len(), *len);
        assert!(is_card(&n), "prefix {p} length {len}: {n} not detected");
    }
}

#[test]
fn d2_a_valid_check_digit_with_a_prefix_or_length_outside_the_ranges_is_not_a_card() {
    let not: Vec<(&str, usize)> = vec![
        ("4", 14),
        ("4", 15),
        ("4", 17),
        ("4", 18), // Visa lengths
        ("51", 15),
        ("51", 17),
        ("55", 19),
        ("2221", 15),
        ("2720", 17), // Mastercard length
        ("50", 16),
        ("56", 16),
        ("2220", 16),
        ("2721", 16), // just outside the Mastercard ranges
        ("34", 16),
        ("37", 14),
        ("37", 16),
        ("33", 15),
        ("35", 15), // Amex needs 15 digits and 34 or 37
        ("6011", 15),
        ("65", 15),
        ("644", 15),
        ("6010", 16),
        ("6012", 16),
        ("66", 16),
        ("643", 16), // Discover
        ("3528", 15),
        ("3527", 16),
        ("3590", 16), // JCB
        ("300", 13),
        ("306", 16),
        ("39", 16),
        ("37", 13), // Diners / outside
        ("62", 15),
        ("63", 16),
        ("61", 16), // UnionPay
        ("99", 16),
        ("10", 16),
        ("70", 16),
        ("12", 15),
    ];
    for (i, (p, len)) in not.iter().enumerate() {
        let n = card(p, *len, 100 + i as u32);
        assert_eq!(n.len(), *len);
        assert!(
            !is_card(&n),
            "prefix {p} length {len}: {n} was taken for a card"
        );
    }
}

#[test]
fn d3_a_wrong_check_digit_is_not_a_card() {
    for (p, len) in [("4", 16), ("51", 16), ("37", 15), ("6011", 16), ("62", 19)] {
        let n = card(p, len, 7);
        let last = n.pop_last_digit();
        let bad = format!("{}{}", &n[..n.len() - 1], (last + 1) % 10);
        assert!(!is_card(&bad), "{bad} has a wrong check digit");
    }
}

trait LastDigit {
    fn pop_last_digit(&self) -> u32;
}
impl LastDigit for String {
    fn pop_last_digit(&self) -> u32 {
        self.chars().last().unwrap().to_digit(10).unwrap()
    }
}

fn credential_hit(text: &str) -> bool {
    let p = policy();
    scan(text, p.detect_cfg()).iter().any(|h| h.det == Det::D3)
}

#[test]
fn d4_placeholder_values_are_not_credentials_and_real_looking_ones_are() {
    let real = "Ab3dE6gH9jK2mN5p";
    assert!(credential_hit(&format!("password = \"{real}\"")));
    for ph in [
        "${DB_PASSWORD}",
        "<your-password>",
        "{{secret_value}}",
        "$(cat /run/secret)",
        "%(password)s",
        "$PASSWORD1",
        "changeme",
        "password",
        "placeholder",
        "yourpassword",
        "redacted",
        "undefined",
        "aaaaaaaa",
        "xxxxxxxx",
        "********",
        "........",
        "x*x*x.x.",
    ] {
        // values shorter than 8 characters are skipped by the pattern itself: pad the plain words to 8 with the same character where needed
        let v = if ph.len() < 8 {
            format!("{ph:<8}")
        } else {
            ph.to_string()
        };
        if v.contains(' ') {
            continue;
        }
        assert!(
            !credential_hit(&format!("password = \"{v}\"")),
            "{v} was taken for a credential"
        );
    }
    // every lead-in of the placeholder list on its own, each followed by a real-looking tail
    for lead in ["${", "<", "{{", "$(", "%(", "$"] {
        assert!(
            !credential_hit(&format!("token = \"{lead}Ab3dE6gH9jK2mN5p\"")),
            "{lead}"
        );
    }
    // a value that is one repeated letter, and one that is a mix of x * . only
    assert!(!credential_hit("secret = \"qqqqqqqqqq\""));
    assert!(!credential_hit("secret = \"x.*x.*x.*x\""));
    assert!(
        credential_hit("secret = \"qqqqqqqqqr\""),
        "one different character makes it a value"
    );
}

#[test]
fn d5_a_connection_string_password_needs_three_characters_and_not_be_a_placeholder() {
    assert!(credential_hit(
        "db at postgres://app:s3cr3tPw@db.example.invalid/x"
    ));
    assert!(
        !credential_hit("db at postgres://app:ab@db.example.invalid/x"),
        "two characters"
    );
    assert!(
        !credential_hit("db at postgres://app:changeme@db.example.invalid/x"),
        "a placeholder"
    );
    assert!(
        credential_hit("db at postgres://app:abc@db.example.invalid/x"),
        "exactly three characters is a password"
    );
}
