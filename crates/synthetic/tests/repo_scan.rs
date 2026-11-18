//! P0 across the whole repository: no canary outside the gate, no valid-range SSN-shaped value anywhere.
//! The only directory allowed to hold canaries is crates/synthetic itself (its tests mint them in memory).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_synthetic::*;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

const TEXT: [&str; 18] = [
    "rs",
    "md",
    "json",
    "toml",
    "txt",
    "py",
    "sh",
    "yml",
    "yaml",
    "xml",
    "html",
    "js",
    "css",
    "ts",
    "tsx",
    "cedar",
    "cedarschema",
    "jsonl",
];

fn walk(dir: &Path, skip: &dyn Fn(&Path) -> bool, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if matches!(
            name.as_str(),
            "target" | ".git" | "node_modules" | "corpus" | "artifacts"
        ) || skip(&p)
        {
            continue;
        }
        if p.is_dir() {
            walk(&p, skip, out);
        } else if p
            .extension()
            .is_some_and(|x| TEXT.contains(&x.to_str().unwrap_or("")))
            && std::fs::metadata(&p).unwrap().len() < 8_000_000
        {
            out.push(p);
        }
    }
}

fn files(skip_synthetic: bool) -> Vec<PathBuf> {
    let r = root();
    let mut out = vec![];
    let skip = move |p: &Path| skip_synthetic && p.starts_with(r.join("crates/synthetic"));
    walk(&root(), &skip, &mut out);
    assert!(out.len() > 100, "the walk found only {} files", out.len());
    out
}

#[test]
fn t1_no_canary_appears_anywhere_outside_the_gate() {
    let mut leaks = vec![];
    for f in files(true) {
        if let Ok(text) = std::fs::read_to_string(&f) {
            if !scan(&text).is_empty() {
                leaks.push(f.display().to_string());
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "canary tokens found outside the gate: {leaks:?}"
    );
}

#[test]
fn t2_the_explorer_bundle_its_golden_responses_and_the_ledger_vectors_hold_no_canary() {
    let r = root();
    for rel in [
        "crates/explorer/tests/golden/bundle_seed1_n5.json",
        "crates/explorer/tests/golden/responses.json",
        "crates/council/tests/vectors/council_v1.json",
    ] {
        let text = std::fs::read_to_string(r.join(rel)).unwrap_or_else(|_| panic!("missing {rel}"));
        assert!(scan(&text).is_empty(), "{rel}");
    }
    // a canary placed into a copy of the bundle IS found, so the check above is not vacuous
    let bundle =
        std::fs::read_to_string(r.join("crates/explorer/tests/golden/bundle_seed1_n5.json"))
            .unwrap();
    let planted = bundle.replacen(
        "\"synthetic\":true",
        &format!("\"synthetic\":true,\"x\":\"{}\"", canary(99)),
        1,
    );
    assert_ne!(planted, bundle);
    assert_eq!(scan(&planted), vec![canary(99)]);
}

/// SSN-shaped tokens: ddd-dd-dddd with no digit or hyphen touching either end.
fn ssn_shaped(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i + 11 <= b.len() {
        let w = &b[i..i + 11];
        let shaped = w.iter().enumerate().all(|(k, c)| {
            if k == 3 || k == 6 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        });
        let before_ok = i == 0 || !(b[i - 1].is_ascii_digit() || b[i - 1] == b'-');
        let after_ok = i + 11 == b.len() || !(b[i + 11].is_ascii_digit() || b[i + 11] == b'-');
        if shaped && before_ok && after_ok {
            out.push(String::from_utf8_lossy(w).to_string());
            i += 11;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn t3_every_ssn_shaped_value_in_the_repository_is_from_a_reserved_invalid_range() {
    let mut found = vec![];
    for f in files(false) {
        if f.starts_with(root().join("docs/archive")) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&f) {
            for s in ssn_shaped(&text) {
                if !is_reserved_invalid_ssn(&s) {
                    found.push(format!(
                        "{}: {s}",
                        f.strip_prefix(root()).unwrap().display()
                    ));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "valid-range SSN-shaped values (could look like real data): {found:?}"
    );
}

#[test]
fn t4_the_ssn_shape_finder_itself_works() {
    // Built at run time from parts so that no valid-range SSN-shaped literal sits in the repository (see ids.rs).
    let (valid_range, other) = (
        format!("{}-{}-{}", "123", "45", "6789"),
        "900-00-0001".to_string(),
    );
    assert_eq!(
        ssn_shaped(&format!("a {valid_range} b {other}")),
        vec![valid_range.clone(), other]
    );
    let not_shaped = format!(
        "1{valid_range} and {valid_range}0 and {} and 2026-10-21",
        "12-345-6789"
    );
    assert!(ssn_shaped(&not_shaped).is_empty());
}

/// SSN-shaped tokens with SPACES: `ddd dd dddd`, no digit or hyphen touching either end (the hyphen form is `ssn_shaped`; this form was not scanned before P0-SYNTH-FIX).
fn ssn_shaped_spaced(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i + 11 <= b.len() {
        let w = &b[i..i + 11];
        let shaped = w.iter().enumerate().all(|(k, c)| {
            if k == 3 || k == 6 {
                *c == b' '
            } else {
                c.is_ascii_digit()
            }
        });
        let before_ok = i == 0 || !(b[i - 1].is_ascii_digit() || b[i - 1] == b'-');
        let after_ok = i + 11 == b.len() || !(b[i + 11].is_ascii_digit() || b[i + 11] == b'-');
        if shaped && before_ok && after_ok {
            out.push(String::from_utf8_lossy(w).to_string());
            i += 11;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn t3b_every_space_separated_ssn_shaped_value_in_the_repository_is_from_a_reserved_invalid_range() {
    let mut found = vec![];
    for f in files(false) {
        if f.starts_with(root().join("docs/archive")) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&f) {
            for s in ssn_shaped_spaced(&text) {
                if !is_reserved_invalid_ssn(&s.replace(' ', "-")) {
                    found.push(format!(
                        "{}: {s}",
                        f.strip_prefix(root()).unwrap().display()
                    ));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "valid-range SSN-shaped values with spaces (could look like real data): {found:?}"
    );
}

#[test]
fn t4b_the_space_separated_finder_itself_works() {
    // built at run time from parts, like t4
    let (valid_range, other) = (
        format!("{} {} {}", "123", "45", "6789"),
        "900 00 0001".to_string(),
    );
    assert_eq!(
        ssn_shaped_spaced(&format!("a {valid_range} b {other}")),
        vec![valid_range.clone(), other]
    );
    let hyphenated = format!("{}-{}-{}", "123", "45", "6789");
    let not_shaped = format!(
        "1{valid_range} and {valid_range}0 and {} and 2026 10 21 and {hyphenated}",
        "12 345 6789"
    );
    assert!(ssn_shaped_spaced(&not_shaped).is_empty());
}

// ---- P0-CARDS: Luhn-valid card-shaped numbers must be listed, with a source, in card-allowlist.txt ----

fn luhn_ok(d: &str) -> bool {
    let mut sum = 0;
    for (i, c) in d.bytes().rev().enumerate() {
        let mut n = u32::from(c - b'0');
        if i % 2 == 1 {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
    }
    sum % 10 == 0
}

/// Digit runs of 13 to 19 digits (single spaces or hyphens allowed between digits), first digit 3 to 6, Luhn-valid, more than three distinct digits, not touching a letter or digit, and not part of a decimal (a dot between digits).
fn card_shaped(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit()
            && (i == 0
                || !(b[i - 1].is_ascii_alphanumeric()
                    || (b[i - 1] == b'.' && i >= 2 && b[i - 2].is_ascii_digit())))
        {
            let (mut j, mut digits) = (i, String::new());
            while j < b.len() {
                if b[j].is_ascii_digit() {
                    digits.push(b[j] as char);
                    j += 1;
                } else if (b[j] == b' ' || b[j] == b'-')
                    && j + 1 < b.len()
                    && b[j + 1].is_ascii_digit()
                    && !digits.is_empty()
                {
                    j += 1;
                } else {
                    break;
                }
            }
            let after_ok = j >= b.len()
                || !(b[j].is_ascii_alphanumeric()
                    || (b[j] == b'.' && j + 1 < b.len() && b[j + 1].is_ascii_digit()));
            let distinct = digits
                .bytes()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            if after_ok
                && (13..=19).contains(&digits.len())
                && matches!(digits.as_bytes()[0], b'3'..=b'6')
                && distinct > 3
                && luhn_ok(&digits)
            {
                out.push(digits);
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

struct Allowed {
    exact: Vec<String>,
    prefixes: Vec<(String, String)>, // (digit prefix, path prefix)
}

fn parse_allowlist(text: &str) -> Result<Allowed, String> {
    let (mut exact, mut prefixes) = (vec![], vec![]);
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((spec, source)) = line.split_once('|') else {
            return Err(format!("line {}: no source after the bar", n + 1));
        };
        if source.trim().len() < 8 {
            return Err(format!(
                "line {}: the source is too short to be a source",
                n + 1
            ));
        }
        let parts: Vec<&str> = spec.split_whitespace().collect();
        match parts.as_slice() {
            ["exact", d] if d.bytes().all(|c| c.is_ascii_digit()) => exact.push((*d).to_string()),
            ["prefix", d, "path", p] if d.bytes().all(|c| c.is_ascii_digit()) => {
                prefixes.push(((*d).to_string(), (*p).to_string()))
            }
            _ => return Err(format!("line {}: not an entry", n + 1)),
        }
    }
    Ok(Allowed { exact, prefixes })
}

fn mask(d: &str) -> String {
    format!("{}…({} digits)", &d[..2], d.len())
}

#[test]
fn t5_every_luhn_valid_card_shaped_number_in_the_repository_is_on_the_allowlist_with_a_source() {
    let allowed = parse_allowlist(
        &std::fs::read_to_string(root().join("crates/synthetic/tests/card-allowlist.txt")).unwrap(),
    )
    .unwrap();
    let mut found = std::collections::BTreeMap::<String, usize>::new();
    for f in files(false) {
        if f.starts_with(root().join("docs/archive")) {
            continue;
        }
        let rel = f
            .strip_prefix(root())
            .unwrap()
            .to_string_lossy()
            .to_string();
        if let Ok(text) = std::fs::read_to_string(&f) {
            for d in card_shaped(&text) {
                let ok = allowed.exact.contains(&d)
                    || allowed.prefixes.iter().any(|(p, path)| {
                        d.starts_with(p.as_str()) && rel.starts_with(path.as_str())
                    });
                if !ok {
                    *found.entry(format!("{rel}: {}", mask(&d))).or_default() += 1;
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "card-shaped numbers not on the allowlist (file: masked value, count): {found:?}"
    );
}

#[test]
fn t6_the_card_finder_and_the_allowlist_parser_work() {
    // built at run time from parts: a published processor test number in three spellings, and a number that fails the checksum
    let plain = format!("{}{}", "37828224", "6310005");
    let spaced = format!("{} {} {}", "3782", "822463", "10005");
    let dashed = format!("{}-{}-{}-{}", "6011", "1111", "1111", "1117");
    let bad_checksum = format!("{}{}", "37828224", "6310006");
    assert_eq!(card_shaped(&format!("a {plain} b")), vec![plain.clone()]);
    assert_eq!(card_shaped(&spaced), vec![plain.clone()]);
    assert_eq!(
        card_shaped(&format!("x {dashed}.")),
        vec![dashed.replace('-', "")]
    );
    assert!(card_shaped(&bad_checksum).is_empty());
    for not in [
        format!("1{plain}"),
        format!("{plain}0"),
        format!("v{plain}"),
        format!("0.{plain}"),
        "4444444444444448".to_string(),
        "1800000000000".to_string(),
    ] {
        assert!(card_shaped(&not).is_empty(), "{not}");
    }
    let ok = parse_allowlist("# c\nexact 3782822463100 05 | x").is_err();
    assert!(ok, "a digit group with a space is not an entry");
    assert!(parse_allowlist("exact 3782822463100 | no bar").is_err());
    assert!(parse_allowlist("exact 3782822463100 |").is_err());
    assert!(parse_allowlist("whatever 1 | a source text").is_err());
    let a = parse_allowlist("exact 378282246310005 | published test number\nprefix 400000 path crates/egress | generated sets").unwrap();
    assert_eq!((a.exact.len(), a.prefixes.len()), (1, 1));
}
