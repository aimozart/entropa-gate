//! Tests added after the first mutation run of S12c: coverage of the generator's whole output space.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_synthetic::*;
use std::collections::BTreeSet;

#[test]
fn g1_the_generator_reaches_every_never_issued_area_and_nothing_else() {
    let areas: BTreeSet<u32> = (0..40_000u64)
        .map(|s| ssn(s)[..3].parse().unwrap())
        .collect();
    let want: BTreeSet<u32> = [0u32, 666].into_iter().chain(900..=999).collect();
    assert_eq!(areas, want);
}

#[test]
fn g2_the_ssn_validator_checks_the_shape_exactly() {
    for bad in [
        "000x12-3456",
        "000-12x3456",
        "000-12-34567",
        "000-12-345",
        "0000-12-3456",
        "000-123-456",
        "00a-12-3456",
        "000-1a-3456",
        "000-12-345a",
        " 000-12-3456",
        "000-12-3456\n",
    ] {
        assert!(!is_reserved_invalid_ssn(bad), "{bad:?}");
    }
    assert!(is_reserved_invalid_ssn("000-12-3456"));
}

#[test]
fn g3_every_fake_first_name_and_surname_is_used() {
    let firsts: BTreeSet<&str> = (0..2_000u64)
        .filter_map(|s| {
            name(s)
                .split_once(' ')
                .map(|(f, _)| FAKE_FIRST_NAMES.iter().copied().find(|x| *x == f).unwrap())
        })
        .collect();
    let lasts: BTreeSet<&str> = (0..2_000u64)
        .filter_map(|s| {
            name(s)
                .split_once(' ')
                .map(|(_, l)| FAKE_SURNAMES.iter().copied().find(|x| *x == l).unwrap())
        })
        .collect();
    assert_eq!(firsts.len(), FAKE_FIRST_NAMES.len());
    assert_eq!(lasts.len(), FAKE_SURNAMES.len());
}

#[test]
fn g4_dates_of_birth_are_valid_dates_over_the_whole_documented_range() {
    let (mut years, mut months, mut days) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for s in 0..3_000u64 {
        let dob = patient(s).unwrap().dob;
        let p: Vec<u32> = dob.split('-').map(|x| x.parse().unwrap()).collect();
        assert_eq!(p.len(), 3, "{dob}");
        assert!(
            (1940..=2005).contains(&p[0]) && (1..=12).contains(&p[1]) && (1..=28).contains(&p[2]),
            "{dob}"
        );
        assert_eq!(dob.len(), 10);
        years.insert(p[0]);
        months.insert(p[1]);
        days.insert(p[2]);
    }
    assert_eq!(years.len(), 66, "every year from 1940 to 2005 occurs");
    assert_eq!(months.len(), 12);
    assert_eq!(days.len(), 28);
}

#[test]
fn g5_the_serial_is_never_0000_and_always_four_digits() {
    // 200,000 fixed seeds: a generator that could emit serial 0000 (1 in 9,999) is caught deterministically
    for s in 0..200_000u64 {
        let v = ssn(s);
        assert!(v.len() == 11 && &v[7..] != "0000", "{v}");
    }
}
