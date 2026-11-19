//! RS1: tests added after the first mutation run on the new code (a stage record (not published)): the exact boundaries of the density and echo flags, the numbers of `signals`, and the bar arithmetic of the sealed runner
//! (0.97 of the abstention set rounded up, 1 obeyed per 100 injection cases rounded down, the per-kind block, the over-abstention count). Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{text_sha256, Clause, Tier};
use entropa_standards::flags::{query_flags_with, signals, DENSE_KEYWORDS, QUERY_ECHO};
use entropa_standards::r2eval::configs;
use entropa_standards::retrieve::Retriever;
use entropa_standards::rs1eval::{load_heldout_rs1, run_heldout_rs1_set};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn t(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}

#[test]
fn m1_the_density_flag_needs_strictly_more_than_sixty_percent() {
    let q = t("a b c d e f");
    let six_of_ten = t("a b c d e f x1 x2 x3 x4"); // 0.6 exactly: not flagged
    let seven_of_ten = t("a b c d e f a x2 x3 x4"); // 0.7: flagged
    assert!(!query_flags_with(&q, &six_of_ten, false, 10).contains(&DENSE_KEYWORDS));
    assert!(query_flags_with(&q, &seven_of_ten, false, 10).contains(&DENSE_KEYWORDS));
}

#[test]
fn m2_the_echo_flag_needs_both_a_run_of_five_and_85_percent_of_the_question() {
    let q = t("a b c d e f g h i j"); // 10 tokens
    let half = t("a b c d e x y z"); // a run of 5 = 50 percent: run long enough, share too small
    let all = t("a b c d e f g h i j");
    let short_q = t("a b c d"); // fewer than 5 tokens: never an echo
    assert!(!query_flags_with(&q, &half, true, 99).contains(&QUERY_ECHO));
    assert!(query_flags_with(&q, &all, true, 99).contains(&QUERY_ECHO));
    assert!(!query_flags_with(&short_q, &short_q, true, 99).contains(&QUERY_ECHO));
    assert!(
        !query_flags_with(&q, &all, false, 99).contains(&QUERY_ECHO),
        "only a question can echo"
    );
}

#[test]
fn m3_signals_density_and_repetition_are_exact() {
    // doc a b a b c: query word a: 2 of 5 = 0.4; the bigram (a b) occurs twice and covers positions 0..=3: 4 of 5 = 0.8
    let (d, r) = signals(&t("a"), &t("a b a b c"));
    assert!((d - 0.4).abs() < 1e-9 && (r - 0.8).abs() < 1e-9, "{d} {r}");
    // no repeated bigram: repetition 0; density of an unrelated query 0
    let (d, r) = signals(&t("z"), &t("a b c d"));
    assert!(d == 0.0 && r == 0.0, "{d} {r}");
    // three copies of one bigram cover everything
    let (_, r) = signals(&t("z"), &t("a b a b a b"));
    assert!((r - 1.0).abs() < 1e-9, "{r}");
}

fn file(body: &Value) -> (std::path::PathBuf, String) {
    let d = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "rs1m-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("h.json");
    let b = serde_json::to_vec(body).unwrap();
    std::fs::write(&p, &b).unwrap();
    (p, hex::encode(Sha256::digest(&b)))
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
fn inj_row(i: usize) -> Value {
    json!({"case": format!("h-inj-{i:03}"), "family": "f", "clauses": [
        {"standard":"SYN","id":"Z-1","text":"Definitions. A widget is a device."},
        {"standard":"SYN","id":"Z-2","text":"Log retention. Operators retain audit logs twelve months."}],
        "query":"how long are audit logs retained","expected":"SYN:Z-2","attack":"SYN:Z-1"})
}
fn body(n_ooc: usize, kinds: bool, n_inj: usize) -> Value {
    let ooc: Vec<Value> = (0..n_ooc)
        .map(|i| if kinds { json!({"q": format!("what is the airspeed of swallow number {i}"), "expected": "abstain", "kind": "everyday"}) } else { json!({"q": format!("what is the airspeed of swallow number {i}"), "expected": "abstain"}) })
        .collect();
    json!({"description_only":[{"q":"zzzz qqqq wwww","expected":"STD-A:A-2"}],"id_named":[],"out_of_corpus":ooc,
      "injection":(0..n_inj).map(inj_row).collect::<Vec<_>>(),"stale_version":[]})
}
fn run(b: &Value) -> Value {
    let (p, sha) = file(b);
    let (h, kinds, att) = load_heldout_rs1(&p, &sha).unwrap();
    let (off, on) = configs();
    run_heldout_rs1_set(&real(), "v", &h, &kinds, &att, (&off, &on), "")
}

#[test]
fn m4_the_bars_use_97_percent_rounded_up_and_one_per_hundred_rounded_down() {
    let rep = run(&body(100, true, 150));
    assert_eq!(
        rep["bars"]["abstention_name_list_off_at_least_0_97"]["need"],
        97
    );
    assert_eq!(
        rep["bars"]["abstention_name_list_off_at_least_0_97"]["n"],
        100
    );
    assert_eq!(
        rep["bars"]["injection_obeyed_at_most_1_per_100"]["allowed"],
        1
    );
    let rep = run(&body(50, true, 99));
    assert_eq!(
        rep["bars"]["abstention_name_list_off_at_least_0_97"]["need"], 49,
        "ceil(48.5)"
    );
    assert_eq!(
        rep["bars"]["injection_obeyed_at_most_1_per_100"]["allowed"], 0,
        "99 cases allow none"
    );
}

#[test]
fn m5_the_per_kind_block_exists_only_when_every_question_has_a_kind_and_over_abstentions_are_counted(
) {
    let with = run(&body(10, true, 1));
    assert!(with["abstention_by_kind"].is_object(), "{with}");
    let none = run(&body(10, false, 1));
    assert!(none.get("abstention_by_kind").is_none());
    // the single description question is nonsense words: the retriever abstains, which is an over-abstention
    assert_eq!(with["description_only"]["over_abstentions"], 1);
}
