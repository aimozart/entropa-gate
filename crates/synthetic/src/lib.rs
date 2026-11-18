//! # entropa-synthetic
//!
//! **P0 rule (the owner, 2026-10-21): patient and client data safety comes first, always, even when mocked.**
//! Identifier-shaped synthetic values come only from reserved INVALID ranges so they can never match a real
//! person; every mock record carries a unique canary token that no prompt, log, ledger event, bundle, public
//! page or model input outside the gate may ever contain; records are generated on demand from a seed rather
//! than stored. Everything here is a pure function of its arguments (no clock, no randomness, no file).

/// Every canary token starts with this text.
pub const CANARY_PREFIX: &str = "ENTROPA-CANARY-";

/// Closed list of fake first names (obviously synthetic).
pub const FAKE_FIRST_NAMES: [&str; 8] = [
    "Avery", "Blair", "Casey", "Devon", "Emery", "Finley", "Harper", "Jordan",
];

/// Closed list of fake surnames; every one ends with `-Syn` so a synthetic name can never be mistaken for a real one.
pub const FAKE_SURNAMES: [&str; 8] = [
    "Alder-Syn",
    "Birch-Syn",
    "Cedar-Syn",
    "Dune-Syn",
    "Elm-Syn",
    "Fern-Syn",
    "Gale-Syn",
    "Heath-Syn",
];

/// One synthetic patient, generated on demand from a seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patient {
    /// Full name from the closed lists.
    pub name: String,
    /// SSN-shaped value from a reserved invalid range.
    pub ssn: String,
    /// Medical record number with the synthetic prefix.
    pub mrn: String,
    /// Phone number in the fictional 555-01XX range.
    pub phone: String,
    /// Email address on the reserved `example.invalid` domain.
    pub email: String,
    /// Date of birth, `YYYY-MM-DD`.
    pub dob: String,
    /// The unique canary token of this record.
    pub canary: String,
}

/// 64 bits derived from the seed and a purpose label: `BLAKE3("entropa-synthetic-v1" 0x00 || label 0x00 || seed LE)`.
fn derive(seed: u64, label: &str) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-synthetic-v1\0");
    h.update(label.as_bytes());
    h.update(b"\0");
    h.update(&seed.to_le_bytes());
    let out = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&out.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

/// Areas that were never issued: 000, 666 and 900-999 (102 values).
const INVALID_AREAS: u64 = 102;

/// An SSN-shaped value (`AAA-00-SSSS`) from a reserved invalid range: an area that was never issued AND the
/// never-issued group `00`, so it is neither an SSN nor an ITIN. The serial is 0001-9999.
pub fn ssn(seed: u64) -> String {
    let pick = derive(seed, "ssn-area") % INVALID_AREAS;
    let area = match pick {
        0 => 0,
        1 => 666,
        n => 900 + (n - 2),
    };
    let serial = 1 + derive(seed, "ssn-serial") % 9999;
    format!("{area:03}-00-{serial:04}")
}

/// True if `s` is SSN-shaped (`ddd-dd-dddd`) and can never have been issued (area 000, 666 or 900-999, group 00,
/// or serial 0000).
pub fn is_reserved_invalid_ssn(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 11 || b.get(3) != Some(&b'-') || b.get(6) != Some(&b'-') {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = s.get(r)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    match (digits(0..3), digits(4..6), digits(7..11)) {
        (Some(area), Some(group), Some(serial)) => {
            area == 0 || area == 666 || area >= 900 || group == 0 || serial == 0
        }
        _ => false,
    }
}

/// A medical record number with the synthetic prefix `SYN-` and eight digits.
pub fn mrn(seed: u64) -> String {
    format!("SYN-{:08}", derive(seed, "mrn") % 100_000_000)
}

/// True if `s` is a well-formed synthetic MRN: `SYN-` and exactly eight digits.
pub fn is_synthetic_mrn(s: &str) -> bool {
    s.strip_prefix("SYN-")
        .is_some_and(|d| d.len() == 8 && d.bytes().all(|c| c.is_ascii_digit()))
}

/// A name from the closed fake lists, `First Last-Syn`.
pub fn name(seed: u64) -> String {
    let first = FAKE_FIRST_NAMES
        .get((derive(seed, "first") % FAKE_FIRST_NAMES.len() as u64) as usize)
        .copied()
        .unwrap_or("Avery");
    let last = FAKE_SURNAMES
        .get((derive(seed, "last") % FAKE_SURNAMES.len() as u64) as usize)
        .copied()
        .unwrap_or("Alder-Syn");
    format!("{first} {last}")
}

/// A US-shaped phone number in the fictional 555-0100..0199 range: `(AAA) 555-01XX`.
pub fn phone(seed: u64) -> String {
    let area = 201 + derive(seed, "phone-area") % 789;
    let line = derive(seed, "phone-line") % 100;
    format!("({area}) 555-01{line:02}")
}

/// True if `s` is a phone number of the exact form `(AAA) 555-01XX`, the fictional range.
pub fn is_reserved_invalid_phone(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 14
        && b.first() == Some(&b'(')
        && b.get(4) == Some(&b')')
        && b.get(5) == Some(&b' ')
        && s.get(1..4)
            .is_some_and(|a| a.bytes().all(|c| c.is_ascii_digit()))
        && s.get(6..12) == Some("555-01")
        && s.get(12..14)
            .is_some_and(|x| x.bytes().all(|c| c.is_ascii_digit()))
}

/// An email address on the reserved `example.invalid` domain.
pub fn email(seed: u64) -> String {
    format!(
        "patient.{:08x}@example.invalid",
        derive(seed, "email") & 0xffff_ffff
    )
}

/// A complete synthetic patient, deterministic in the seed; nothing is stored anywhere.
pub fn patient(seed: u64) -> Option<Patient> {
    let year = 1940 + derive(seed, "dob-year") % 66;
    let month = 1 + derive(seed, "dob-month") % 12;
    let day = 1 + derive(seed, "dob-day") % 28;
    Some(Patient {
        name: name(seed),
        ssn: ssn(seed),
        mrn: mrn(seed),
        phone: phone(seed),
        email: email(seed),
        dob: format!("{year:04}-{month:02}-{day:02}"),
        canary: canary(seed),
    })
}

/// The unique canary token of a seed: `ENTROPA-CANARY-` + 16 lower-case hex digits.
pub fn canary(seed: u64) -> String {
    format!("{CANARY_PREFIX}{:016x}", derive(seed, "canary"))
}

/// Every canary-shaped token found in `text`, in order of appearance: the prefix followed by 16 lower-case hex digits
/// (a longer run of digits still yields the first sixteen, so a longer token cannot hide a canary).
pub fn scan(text: &str) -> Vec<String> {
    let mut found = vec![];
    let mut from = 0;
    while let Some(rel) = text.get(from..).and_then(|t| t.find(CANARY_PREFIX)) {
        let start = from + rel;
        let digits_at = start + CANARY_PREFIX.len();
        match text.get(digits_at..digits_at + 16) {
            Some(d)
                if d.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) =>
            {
                found.push(format!("{CANARY_PREFIX}{d}"));
                from = digits_at + 16;
            }
            _ => from = start + 1,
        }
    }
    found
}
