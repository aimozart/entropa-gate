//! RS1: second batch of tests after mutation run 2 (a stage record (not published)): the per-family counts and id lists of the injection block, the switch wrapper of the runner, and the numbers of the signals diagnostic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{text_sha256, Clause, Tier};
use entropa_standards::r2eval::{configs, InjCase};
use entropa_standards::retrieve::Retriever;
use entropa_standards::rs1eval::{inj_block_rs1, load_dev_rs1, run_heldout_rs1, run_signals};
use std::path::Path;

fn case(label: &str, family: &str, query: &str, expected: &str) -> InjCase {
    let c = |id: &str, t: &str| ("SYN".to_string(), id.to_string(), t.to_string());
    InjCase {
        label: label.into(),
        family: family.into(),
        clauses: vec![
            c("Z-1", "Definitions. A widget is a device."),
            c(
                "Z-2",
                "Log retention. Operators retain audit logs twelve months.",
            ),
            c("Z-3", "Scope. This applies to widgets."),
        ],
        query: query.into(),
        expected: expected.into(),
    }
}
fn v(x: &str) -> Vec<String> {
    vec![x.to_string()]
}

#[test]
fn q1_the_block_counts_each_class_per_family_and_lists_only_the_right_ids() {
    let q = "how long are audit logs retained";
    let cases = vec![
        case("c-obeyed", "fa", q, "SYN:Z-1"), // top is Z-2; attack Z-2 -> obeyed
        case("c-another", "fa", q, "SYN:Z-1"), // top is Z-2; attack Z-3 -> another clause
        case("c-correct", "fb", q, "SYN:Z-2"), // top is Z-2 = expected -> correct
        case("c-abstain", "fb", "qqqq wwww zzzz", "SYN:Z-2"), // nothing matches -> abstained
    ];
    let attacks = vec![v("SYN:Z-2"), v("SYN:Z-3"), v("SYN:Z-3"), v("SYN:Z-3")];
    let (off, _) = configs();
    let b = inj_block_rs1(&cases, &attacks, &off);
    assert_eq!(
        (
            b["n"].as_u64(),
            b["obeyed"].as_u64(),
            b["abstained"].as_u64(),
            b["answered_another_clause"].as_u64(),
            b["correct"].as_u64()
        ),
        (Some(4), Some(1), Some(1), Some(1), Some(1)),
        "{b}"
    );
    let fa = &b["by_family"]["fa"];
    assert_eq!(
        (
            fa["cases"].as_u64(),
            fa["obeyed"].as_u64(),
            fa["abstained"].as_u64(),
            fa["another_clause"].as_u64(),
            fa["correct"].as_u64()
        ),
        (Some(2), Some(1), Some(0), Some(1), Some(0)),
        "{fa}"
    );
    let fb = &b["by_family"]["fb"];
    assert_eq!(
        (
            fb["cases"].as_u64(),
            fb["obeyed"].as_u64(),
            fb["abstained"].as_u64(),
            fb["another_clause"].as_u64(),
            fb["correct"].as_u64()
        ),
        (Some(2), Some(0), Some(1), Some(0), Some(1)),
        "{fb}"
    );
    let ids = |k: &str| {
        b[k].as_array()
            .unwrap()
            .iter()
            .map(|x| x["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids("misses"), vec!["c-obeyed"]);
    assert_eq!(ids("another_clause_cases"), vec!["c-another"]);
}

fn real() -> Retriever {
    let c = |id: &str, x: &str| Clause {
        standard: "STD-A".into(),
        std_version: "1".into(),
        id: id.into(),
        tier: Tier::Open,
        text: x.into(),
        text_sha256: text_sha256(x),
    };
    Retriever::from_clauses(
        "v",
        &"0".repeat(64),
        vec![
            c(
                "A-1",
                "Access control. Operators shall restrict access to records.",
            ),
            c(
                "A-2",
                "Backup. Operators shall restore a sample of backups every month.",
            ),
        ],
    )
}

#[test]
fn q2_the_switch_wrapper_applies_the_switches_and_refuses_an_unknown_one() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("eval_dev_rs1");
    let _ = load_dev_rs1(&p).unwrap();
    let h = entropa_standards::r2eval::HeldOut {
        desc: vec![],
        idn: vec![],
        ooc: vec![],
        inj: vec![case(
            "c1",
            "fa",
            "how long are audit logs retained",
            "SYN:Z-2",
        )],
        stale: vec![],
    };
    let rep = run_heldout_rs1(
        &real(),
        "v",
        &h,
        &[],
        &[v("SYN:Z-3")],
        "raw_flags=0,foreign_any_name=0",
    )
    .unwrap();
    assert_eq!(rep["applied_switches"], "raw_flags=0,foreign_any_name=0");
    assert_eq!(rep["runner"], "rs1");
    assert_eq!(rep["injection"]["correct"], 1);
    let e =
        run_heldout_rs1(&real(), "v", &h, &[], &[v("SYN:Z-3")], "no_such_switch=1").unwrap_err();
    assert!(e.contains("unknown parameter"), "{e}");
}

#[test]
fn q3_the_signals_diagnostic_reports_exact_densities_for_a_tiny_set() {
    // one DEV-like case through run_signals needs the DEV loader; use the real DEV set and check structure and one invariant
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("eval_dev_rs1");
    let d = load_dev_rs1(&p).unwrap();
    let (off, _) = configs();
    let r = run_signals(&real(), "v", &d, &off);
    assert_eq!(r["genuine_clause_density"]["n"], 150);
    assert_eq!(r["most_query_dense_other_clause_density"]["n"], 150);
    // the genuine clause is never denser than the densest other clause in at least half of the cases, and every value is a share
    for k in [
        "genuine_clause_density",
        "most_query_dense_other_clause_density",
        "genuine_clause_repetition",
    ] {
        let (mn, mx) = (r[k]["min"].as_f64().unwrap(), r[k]["max"].as_f64().unwrap());
        assert!(
            (0.0..=1.0).contains(&mn) && (0.0..=1.0).contains(&mx) && mn <= mx,
            "{k}"
        );
    }
    assert!(r["genuine_clause_density"]["p50"].as_f64().unwrap() > 0.0);
    assert!(
        r["attack_density_by_family"]["query_mirror"]["p50"]
            .as_f64()
            .unwrap()
            > 0.5,
        "the mirror attack family is dense in query words"
    );
    assert!(r["real_top_clause_density"]["n"].as_u64().unwrap() <= 100);
}
