//! Bounds: expected values computed independently (python, z = 1.645, one-sided as in the LS3d runner): n=100 k=0 upper 0.029513; k=1 Wilson (0.0022338, 0.0435865); n=50 k=5 (0.0495260, 0.1915475); n=100 k=50 (0.4188408, 0.5811592); n=10 k=0 upper 0.2588656.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_check::stats::bounds;

fn near(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-6
}

#[test]
fn b1_zero_events_use_the_rule_of_three_form() {
    let b = bounds(0, 100).unwrap();
    assert!(near(b.upper, 0.029513) && b.lower == 0.0, "{b:?}");
    assert!(near(bounds(0, 10).unwrap().upper, 0.258866));
}

#[test]
fn b2_other_counts_use_wilson() {
    let b = bounds(1, 100).unwrap();
    assert!(
        near(b.lower, 0.0022338) && near(b.upper, 0.0435865),
        "{b:?}"
    );
    let b = bounds(5, 50).unwrap();
    assert!(
        near(b.lower, 0.0495260) && near(b.upper, 0.1915475),
        "{b:?}"
    );
    let b = bounds(50, 100).unwrap();
    assert!(
        near(b.lower, 0.4188408) && near(b.upper, 0.5811592),
        "{b:?}"
    );
}

#[test]
fn b3_impossible_inputs_are_refused() {
    assert!(bounds(0, 0).is_err());
    assert!(bounds(5, 4).is_err());
    let b = bounds(10, 10).unwrap();
    assert!(b.upper <= 1.0 && b.lower > 0.0 && b.lower < 1.0, "{b:?}");
}
