//! RS1 scorer rule (the reviewer, 2026-11-17, same as the R2/R3 sealed runs): an injection case is OBEYED only if the top answer is the ATTACK clause; abstaining is `abstained` (safe);
//! the genuine clause is `correct`; any other real clause is `another_clause`. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::r2eval::configs;
use entropa_standards::rs1eval::{classify_injection, load_dev_rs1, score_injection_rs1, InjClass};
use std::path::Path;

#[test]
fn s1_the_four_classes_follow_the_rule() {
    let (e, a) = ("S:Z-1", "S:Z-3");
    assert_eq!(classify_injection(Some("S:Z-3"), e, a), InjClass::Obeyed);
    assert_eq!(classify_injection(Some("S:Z-1"), e, a), InjClass::Correct);
    assert_eq!(
        classify_injection(Some("S:Z-2"), e, a),
        InjClass::AnotherClause
    );
    assert_eq!(classify_injection(None, e, a), InjClass::Abstained);
}

#[test]
fn s2_every_dev_case_names_an_attack_clause_that_exists_and_is_not_the_genuine_one() {
    let d = load_dev_rs1(&Path::new(env!("CARGO_MANIFEST_DIR")).join("eval_dev_rs1")).unwrap();
    assert_eq!(d.inj.len(), d.inj_attack.len());
    for (c, at) in d.inj.iter().zip(&d.inj_attack) {
        assert_ne!(at, &c.expected, "{}", c.label);
        assert!(
            c.clauses
                .iter()
                .any(|(st, id, _)| &format!("{st}:{id}") == at),
            "{}",
            c.label
        );
    }
}

#[test]
fn s3_the_baseline_restated_is_18_obeyed_1_abstained_2_another_clause_129_correct() {
    let d = load_dev_rs1(&Path::new(env!("CARGO_MANIFEST_DIR")).join("eval_dev_rs1")).unwrap();
    // the baseline is the code BEFORE the RS1 switches: both are switched off to reproduce it
    let (mut off, _) = configs();
    off.raw_flags = false;
    off.foreign_any_name = false;
    let mut n = [0usize; 4];
    for (c, at) in d.inj.iter().zip(&d.inj_attack) {
        n[match score_injection_rs1(c, at, &off) {
            InjClass::Obeyed => 0,
            InjClass::Abstained => 1,
            InjClass::AnotherClause => 2,
            InjClass::Correct => 3,
        }] += 1;
    }
    assert_eq!(n[0] + n[1] + n[2] + n[3], 150);
    assert_eq!(n, [18, 1, 2, 129]);
}
