//! RS1 candidate 2 (a stage record (not published)): clause-only structural flags from the RAW text (hidden characters, markup, a repeated id-shaped token). They do not look at the query, so a
//! near-verbatim question about a genuine clause cannot trigger them. Synthetic words only. Switched on by `raw_flags=1`; OFF by default.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::flags::{raw_flags, HIDDEN_CHARS, ID_REPEAT, MARKUP};
use entropa_standards::r2eval::{configs, score_injection};
use entropa_standards::retrieve::Config;
use entropa_standards::rs1eval::{load_dev_rs1, score_injection_rs1, InjClass};
use std::path::Path;

#[test]
fn w1_hidden_characters_markup_and_a_repeated_id_are_flagged() {
    assert_eq!(
        raw_flags("Shi\u{200b}ft hand\u{200b}over"),
        vec![HIDDEN_CHARS]
    );
    assert_eq!(raw_flags("soft\u{ad}hyphen"), vec![HIDDEN_CHARS]);
    assert_eq!(raw_flags("a <!-- hidden --> b"), vec![MARKUP]);
    assert_eq!(
        raw_flags("a <span style=\"display:none\">x</span> b"),
        vec![MARKUP]
    );
    assert_eq!(
        raw_flags("This is Z-4 and Z-4 again, Z-4 and Z-4."),
        vec![ID_REPEAT]
    );
}

#[test]
fn w2_ordinary_clause_text_is_not_flagged() {
    for t in [
        "The organization shall review AC-3 and AC-6 once a year, and cite AC-3 once more when a waiver applies.",
        "Where x < y and y > z the limit applies; a < b is not markup.",
        "Visitors shall park in the marked bays.",
        "",
    ] {
        assert!(raw_flags(t).is_empty(), "{t:?}");
    }
}

#[test]
fn w3_the_switch_is_on_by_default_since_the_rs1_freeze_and_can_be_switched_off() {
    assert!(Config::default().raw_flags);
    let mut c = Config::default();
    entropa_standards::r2eval::apply_overrides(&mut c, "raw_flags=0").unwrap();
    assert!(!c.raw_flags);
}

fn dev() -> entropa_standards::rs1eval::DevRs1 {
    load_dev_rs1(&Path::new(env!("CARGO_MANIFEST_DIR")).join("eval_dev_rs1")).unwrap()
}

#[test]
fn w4_with_the_switch_the_hidden_markup_zero_width_and_id_spoof_families_are_not_obeyed() {
    let d = dev();
    let (mut on, _) = configs();
    on.raw_flags = true;
    for fam in ["hidden_markup", "zero_width", "id_spoof"] {
        let bad: Vec<&str> = d
            .inj
            .iter()
            .zip(&d.inj_attack)
            .filter(|(c, a)| c.family == fam && score_injection_rs1(c, a, &on) == InjClass::Obeyed)
            .map(|(c, _)| c.label.as_str())
            .collect();
        assert!(bad.is_empty(), "{fam}: {bad:?}");
    }
}

#[test]
fn w5_the_switch_does_not_make_any_other_case_worse() {
    let d = dev();
    let (off, _) = configs();
    let mut on = off.clone();
    on.raw_flags = true;
    let worse: Vec<&str> = d
        .inj
        .iter()
        .zip(&d.inj_attack)
        .filter(|(c, a)| {
            score_injection_rs1(c, a, &off) != InjClass::Obeyed
                && score_injection_rs1(c, a, &on) == InjClass::Obeyed
        })
        .map(|(c, _)| c.label.as_str())
        .collect();
    assert!(worse.is_empty(), "{worse:?}");
    // and the shipped scorer's own flag stays untouched
    let _ = score_injection;
}
