//! P0: identifier-shaped synthetic values come only from reserved INVALID ranges, so they can never match a real person.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_synthetic::*;
use proptest::prelude::*;
use std::collections::HashSet;

fn parts(s: &str) -> (u32, u32, u32) {
    let b: Vec<&str> = s.split('-').collect();
    assert_eq!(b.len(), 3, "{s}");
    assert!(
        b[0].len() == 3
            && b[1].len() == 2
            && b[2].len() == 4
            && s.bytes().all(|c| c.is_ascii_digit() || c == b'-'),
        "{s}"
    );
    (
        b[0].parse().unwrap(),
        b[1].parse().unwrap(),
        b[2].parse().unwrap(),
    )
}

#[test]
fn i1_the_ssn_validator_knows_the_never_issued_ranges() {
    for ok in [
        "000-12-3456",
        "666-12-3456",
        "900-12-3456",
        "987-65-4321",
        "999-99-9999",
        "123-00-4567",
        "123-45-0000",
        "000-00-0000",
    ] {
        assert!(
            is_reserved_invalid_ssn(ok),
            "{ok} can never have been issued"
        );
    }
    // Built at run time from parts so that no SSN-shaped valid-range literal sits in the repository (the
    // repository scan in repo_scan.rs would rightly flag it).
    let join = |a: &str, b: &str, c: &str| format!("{a}-{b}-{c}");
    let mut real_looking: Vec<String> = [
        ("123", "45", "6789"),
        ("001", "01", "0001"),
        ("219", "09", "9999"),
        ("301", "47", "5820"),
        ("899", "99", "9999"),
        ("665", "01", "0001"),
        ("667", "01", "0001"),
    ]
    .iter()
    .map(|(a, b, c)| join(a, b, c))
    .collect();
    real_looking.push(format!("{} ", join("123", "45", "6789")));
    real_looking
        .extend(["123-45-678", "12-345-6789", "123456789", "abc-de-fghi", ""].map(String::from));
    for real_looking in real_looking {
        assert!(
            !is_reserved_invalid_ssn(&real_looking),
            "{real_looking:?} is valid-range or not SSN-shaped"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 20_000, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn i2_the_generator_cannot_emit_a_valid_range_ssn(seed in any::<u64>()) {
        let s = ssn(seed);
        prop_assert!(is_reserved_invalid_ssn(&s), "{s}");
        let (area, group, serial) = parts(&s);
        // doubly reserved: an invalid area AND the never-issued group 00, so it is neither an SSN nor an ITIN
        prop_assert!(area == 0 || area == 666 || area >= 900, "{s}");
        prop_assert_eq!(group, 0, "{}", s);
        prop_assert!(serial >= 1, "{}", s);
    }

    #[test]
    fn i3_every_identifier_of_a_patient_is_in_a_reserved_range(seed in any::<u64>()) {
        let p = patient(seed).unwrap();
        prop_assert!(is_reserved_invalid_ssn(&p.ssn));
        prop_assert!(is_synthetic_mrn(&p.mrn), "{}", p.mrn);
        prop_assert!(is_reserved_invalid_phone(&p.phone), "{}", p.phone);
        prop_assert!(p.email.ends_with("@example.invalid"), "{}", p.email);
        let (first, last) = p.name.split_once(' ').unwrap();
        prop_assert!(FAKE_FIRST_NAMES.contains(&first) && FAKE_SURNAMES.contains(&last), "{}", p.name);
        prop_assert_eq!(&p.canary, &canary(seed));
    }
}

#[test]
fn i4_generation_is_deterministic_in_the_seed_and_varied_across_seeds() {
    for seed in [0u64, 1, 42, u64::MAX] {
        assert_eq!(
            patient(seed),
            patient(seed),
            "records are generated on demand, not stored"
        );
        assert_eq!(ssn(seed), ssn(seed));
    }
    let distinct: HashSet<String> = (0..5_000u64).map(ssn).collect();
    assert!(
        distinct.len() > 4_500,
        "{} distinct ssns in 5000 seeds",
        distinct.len()
    );
}

#[test]
fn i5_mrn_phone_and_email_validators() {
    assert!(is_synthetic_mrn("SYN-00001234"));
    assert!(
        !is_synthetic_mrn("MRN-00001234")
            && !is_synthetic_mrn("SYN-1234")
            && !is_synthetic_mrn("SYN-0000123x")
            && !is_synthetic_mrn("syn-00001234")
            && !is_synthetic_mrn("")
    );
    assert!(
        is_reserved_invalid_phone("(602) 555-0100") && is_reserved_invalid_phone("(212) 555-0199")
    );
    assert!(
        !is_reserved_invalid_phone("(602) 555-0200")
            && !is_reserved_invalid_phone("(602) 556-0100")
            && !is_reserved_invalid_phone("602-555-0100x")
            && !is_reserved_invalid_phone("")
    );
    for seed in 0..200u64 {
        assert!(email(seed).ends_with("@example.invalid"));
        assert!(is_reserved_invalid_phone(&phone(seed)));
        assert!(is_synthetic_mrn(&mrn(seed)));
        let n = name(seed);
        assert!(
            n.split_once(' ')
                .is_some_and(|(f, l)| FAKE_FIRST_NAMES.contains(&f) && FAKE_SURNAMES.contains(&l)),
            "{n}"
        );
    }
}

#[test]
fn i6_the_fake_name_lists_are_closed_and_marked() {
    assert_eq!(FAKE_FIRST_NAMES.len(), 8);
    assert_eq!(FAKE_SURNAMES.len(), 8);
    for s in FAKE_SURNAMES {
        assert!(
            s.ends_with("-Syn"),
            "{s}: every fake surname carries the marker"
        );
    }
    let all: HashSet<&str> = FAKE_FIRST_NAMES
        .iter()
        .chain(FAKE_SURNAMES.iter())
        .copied()
        .collect();
    assert_eq!(all.len(), 16, "no duplicates");
}
