//! EG1f mutation survivors, part 2: pipeline v2 and the containment layer (docs/evidence/eg1f/mutation-run3-missed.txt). Written AFTER the code, to kill the survivors of mutation run 3.
//! Expected values come from the rules in a stage record (not published) (a downgrade only for a plain text body whose only block is the heuristic D3 and whose every match is a reference; the walk limits
//! 64 deep and 20,000 strings; the worst action wins and the first of equals is kept; every limit is inclusive). Synthetic words only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common_f;
use common_f::*;
use entropa_egress::contain::{check, Kind, Refusal, Schema};
use entropa_egress::decide::{Action, Attachment, Request};
use entropa_egress::eval::{load_policy, policy_from_extra, DEV_KEY};
use entropa_egress::policy::{sign_dev, template_json, Policy, Tier};
use entropa_egress::v2::{decide_contained, decide_v2, Outcome};
use serde_json::{json, Value};

const DEST: &str = "https://api.model.example/v1/chat";
const PS: &str = "$password = Read-Host -AsSecureString";
const PHP: &str = "'password' => 'island ember 42! harbor'";

fn req(body: &str) -> Request {
    Request {
        destination: DEST.into(),
        body: body.as_bytes().to_vec(),
        body_is_json: false,
        attachments: vec![],
        headers: vec![],
    }
}
fn run(r: &Request) -> Outcome {
    decide_v2(r, &policy_of("eval_dev_f"), Tier::T1, &conv(), &Null)
}

/// A policy with the template's tier T3 limits raised, so the walk limits of v2 (64 deep, 20,000 strings) are reachable (the guard's own limits are lower).
fn wide_policy() -> Policy {
    let extra: Value = serde_json::from_str(
        &std::fs::read_to_string(dir("eval_dev_f").join("eg_policy_extra.json")).unwrap(),
    )
    .unwrap();
    let mut v: Value = serde_json::from_str(&policy_from_extra(&extra)).unwrap();
    v["limits"]["T3"] = json!({"bytes":1048576,"depth":120,"fields":100000,"attachments":8,"attachment_bytes":4194304,"tail_bytes":8192});
    v.as_object_mut().unwrap().remove("signature");
    load_policy(&sign_dev(&v.to_string(), DEV_KEY)).unwrap()
}
fn wide(body: &str) -> Outcome {
    let mut r = req(body);
    r.body_is_json = true;
    decide_v2(&r, &wide_policy(), Tier::T3, &conv(), &Null)
}

#[test]
fn w1_the_downgrade_is_only_for_a_plain_body_to_an_allowed_destination() {
    // the base case: the guard's heuristic blocks a harmless PowerShell assignment, v2 lifts it
    let o = run(&req(PS));
    assert_eq!((o.action, o.reason.as_str()), (Action::Allow, "clean"));
    // a denied destination has no detector at all: the block stands
    let mut r = req(PS);
    r.destination = "https://evil.example/x".into();
    let o = run(&r);
    assert_eq!(
        (o.action, o.reason.as_str()),
        (Action::Block, "destination_denied")
    );
    // a header, an attachment or a JSON flag each make the request not plain: the block stands
    let mut r = req(PS);
    r.headers = vec![("X-Note".into(), "hello".into())];
    assert_eq!(run(&r).action, Action::Block, "header");
    let mut r = req(PS);
    r.attachments = vec![Attachment {
        name: "a".into(),
        mime: "text/plain".into(),
        bytes: b"hello".to_vec(),
    }];
    assert_eq!(run(&r).action, Action::Block, "attachment");
    let mut r = req(PS);
    r.body_is_json = true;
    assert_eq!(run(&r).action, Action::Block, "json flag");
}

#[test]
fn w2_the_downgrade_needs_every_heuristic_match_to_be_covered_by_a_reference() {
    // the second match ("$pwd = Read-Host") is not an assignment to a secret key context, so nothing covers it: the block stands
    let o = run(&req("$password = Get-Secret $pwd = Read-Host"));
    assert_eq!(
        (o.action, o.reason.as_str()),
        (Action::Block, "credential_structure")
    );
    // a heuristic match with no reference at all stays blocked
    assert_eq!(run(&req("$pwd = Read-Host")).action, Action::Block);
    // two references, both covered: lifted
    assert_eq!(
        run(&req("$passwd = Read-Host $password = Get-Secret")).action,
        Action::Allow
    );
    // a real secret next to a reference is never lifted
    assert_eq!(
        run(&req(
            "password = $env:DB_PWD and then token = abc123XYZ789qq"
        ))
        .action,
        Action::Block
    );
}

#[test]
fn w3_the_walk_reads_nested_arrays_to_depth_64_and_not_deeper() {
    let nest = |n: usize| format!("{}{:?}{}", "[".repeat(n), PHP, "]".repeat(n));
    let o = wide(&nest(1));
    assert_eq!(
        (o.action, o.reason.as_str()),
        (Action::Block, "context_secret"),
        "one level"
    );
    let o = wide(&nest(64));
    assert_eq!(
        (o.action, o.reason.as_str()),
        (Action::Block, "context_secret"),
        "64 levels are read"
    );
    let o = wide(&nest(65));
    assert_eq!(
        (o.action, o.reason.as_str()),
        (Action::Allow, "clean"),
        "65 levels are beyond the walk limit (stated limit, not a claim of safety)"
    );
}

#[test]
fn w4_the_walk_reads_nested_objects_to_depth_64_and_not_deeper() {
    let nest = |n: usize| {
        format!(
            "{}{:?}{}",
            "{\"password\":".repeat(n - 1) + "{\"password\":",
            "island ember 42! harbor",
            "}".repeat(n)
        )
    };
    let o = wide(&nest(2));
    assert_eq!(o.action, Action::Block, "two levels");
    assert_eq!(wide(&nest(65)).action, Action::Block, "65 objects deep: still read");
    assert_eq!(
        wide(&nest(66)).action,
        Action::Allow,
        "66 objects deep: beyond the walk limit"
    );
}

#[test]
fn w5_the_walk_reads_20001_strings_and_not_more() {
    let many = |filler: usize| {
        let f = vec!["\"\""; filler].join(",");
        format!("[{f},{PHP:?}]")
    };
    let o = wide(&many(20_000));
    assert_eq!(
        (o.action, o.reason.as_str()),
        (Action::Block, "context_secret"),
        "the 20,001st string is read"
    );
    let o = wide(&many(20_001));
    assert_eq!(
        (o.action, o.reason.as_str()),
        (Action::Allow, "clean"),
        "the 20,002nd string is beyond the walk limit"
    );
}

#[test]
fn w6_strings_inside_arrays_are_read() {
    let o = wide(&format!("[{PHP:?}]"));
    assert_eq!(o.reason, "context_secret");
}

#[test]
fn w7_the_worst_action_wins_and_the_first_of_equals_is_kept() {
    let schema = Schema {
        fields: vec![
            ("a".into(), Kind::FreeText { max: 200 }),
            ("b".into(), Kind::FreeText { max: 200 }),
        ],
    };
    let p = policy_of("eval_dev_f");
    let go = |a: &str, b: &str| {
        let payload = json!({"a": a, "b": b}).to_string();
        decide_contained(&schema, payload.as_bytes(), &p, Tier::T1, &conv(), &Null).unwrap()
    };
    // both block, with different reasons: the first one is kept
    let o = go("$pwd = Read-Host", PHP);
    assert_eq!(
        (o.action, o.reason.as_str()),
        (Action::Block, "credential_structure")
    );
    let o = go(PHP, "$pwd = Read-Host");
    assert_eq!(
        (o.action, o.reason.as_str()),
        (Action::Block, "context_secret")
    );
    // a later block beats an earlier allow
    let o = go("hello there", PHP);
    assert_eq!(o.reason, "context_secret");
}

// ---- containment boundaries (every limit is inclusive) ----

fn schema() -> Schema {
    Schema {
        fields: vec![
            ("ref".into(), Kind::Id { max: 32 }),
            ("count".into(), Kind::Int { min: 0, max: 1000 }),
            ("note".into(), Kind::FreeText { max: 2000 }),
            ("big".into(), Kind::FreeText { max: 100_000 }),
        ],
    }
}
fn chk(v: &Value) -> Result<(), Refusal> {
    check(&schema(), v.to_string().as_bytes()).map(|_| ())
}

#[test]
fn w8_ids_ints_and_free_text_accept_their_exact_limits_and_refuse_one_beyond() {
    assert_eq!(chk(&json!({"ref": "a".repeat(32)})), Ok(()));
    assert_eq!(chk(&json!({"ref": "a".repeat(33)})), Err(Refusal::TooLong));
    assert_eq!(chk(&json!({"count": 0})), Ok(()));
    assert_eq!(chk(&json!({"count": 1000})), Ok(()));
    assert_eq!(chk(&json!({"count": -1})), Err(Refusal::OutOfRange));
    assert_eq!(chk(&json!({"count": 1001})), Err(Refusal::OutOfRange));
    assert_eq!(chk(&json!({"note": "a".repeat(2000)})), Ok(()));
    assert_eq!(
        chk(&json!({"note": "a".repeat(2001)})),
        Err(Refusal::TooLong)
    );
    // length is counted in characters, not bytes
    assert_eq!(chk(&json!({"note": "é".repeat(2000)})), Ok(()));
    assert_eq!(chk(&json!({"ref": "é"})), Err(Refusal::OutOfRange));
}

#[test]
fn w9_the_payload_limit_is_65536_bytes_inclusive() {
    let at = |n: usize| format!("{{\"big\":\"{}\"}}", "a".repeat(n));
    let exact = at(65_536 - 10);
    assert_eq!(exact.len(), 65_536);
    assert!(check(&schema(), exact.as_bytes()).is_ok(), "exactly 65,536 bytes");
    let over = at(65_536 - 9);
    assert_eq!(over.len(), 65_537);
    assert_eq!(
        check(&schema(), over.as_bytes()).unwrap_err(),
        Refusal::TooLarge
    );
}

#[test]
fn w10_every_refusal_has_its_own_closed_word() {
    let words = [
        (Refusal::NotJson, "not_json"),
        (Refusal::DuplicateKey, "duplicate_key"),
        (Refusal::NotObject, "not_object"),
        (Refusal::UnknownField, "unknown_field"),
        (Refusal::WrongType, "wrong_type"),
        (Refusal::OutOfRange, "out_of_range"),
        (Refusal::TooLong, "too_long"),
        (Refusal::Nested, "nested"),
        (Refusal::TooLarge, "too_large"),
    ];
    for (r, w) in words {
        assert_eq!(r.to_string(), w);
    }
}

#[test]
fn w11_the_template_policy_builds_for_the_wide_tests() {
    // guards the helper used above: the raised T3 limits must be what the walk tests think they are
    let t: Value = serde_json::from_str(&template_json("api.model.example")).unwrap();
    assert_eq!(t["limits"]["T3"]["depth"], 32);
}
