//! S4c: boundary and single-fault tests added after the first mutation run (each field check is
//! exercised with exactly one bad field, and each numeric limit at and just past its edge).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::ActionClass;
use entropa_core::Probe;
use entropa_policy::*;
use serde_json::{json, Value};

fn valid() -> Value {
    let e = reference();
    let r = req(class(ActionClass::Deploy), RoleName::Ai);
    let d = decide(&e, &r, &allowed(false));
    let rec = sign_record(&Probe::spawn(), ACTOR, &r, &d, &e.policy_set_hash(), NOW).unwrap();
    serde_json::from_str(&rec.payload).unwrap()
}

fn with(key: &str, v: Value) -> Result<DecisionRecord, PolicyError> {
    let mut m = valid();
    m[key] = v;
    decode_record(&m.to_string())
}

#[test]
fn b1_an_untouched_record_decodes() {
    assert!(decode_record(&valid().to_string()).is_ok());
}

#[test]
fn b2_each_field_is_checked_on_its_own() {
    let bad_hex16 = json!("ABCDEF0123456789");
    let bad_hex64 = json!("A".repeat(64));
    for (k, v) in [
        ("actor", bad_hex16.clone()),
        ("principal", bad_hex16),
        ("subject_hash", bad_hex64.clone()),
        ("policy_set_hash", bad_hex64),
        ("cedar", json!("maybe")),
        ("final", json!("none")),
        ("approval_state", json!("whatever")),
        ("reason", json!("whatever")),
        ("approval_attested", json!("yes")),
        ("enforced", json!(1)),
        ("sig", json!("")),
        ("sig", json!("abc")),
        ("sig", json!("ABCD")),
    ] {
        assert!(with(k, v.clone()).is_err(), "{k}={v} must be rejected");
    }
}

#[test]
fn b3_numeric_and_length_limits_at_the_edge() {
    assert!(with("ts", json!((1u64 << 53) - 1)).is_ok());
    assert!(with("ts", json!(1u64 << 53)).is_err());
    assert!(with("determining", json!(vec!["p"; 64])).is_ok());
    assert!(with("determining", json!(vec!["p"; 65])).is_err());
    assert!(with("errors", json!(vec!["p"; 65])).is_err());
    assert!(with("sig", json!("ab".repeat(3309))).is_ok());
    assert!(with("sig", json!("ab".repeat(3310))).is_err());
}

#[test]
fn b4_now_is_accepted_up_to_i64_max_and_no_further() {
    let e = reference();
    let mut r = req(Action::ReadLog, RoleName::Ai);
    r.now = i64::MAX as u64;
    assert_eq!(decide(&e, &r, &allowed(false)).outcome, Outcome::Allow);
    r.now = i64::MAX as u64 + 1;
    assert_eq!(
        decide(&e, &r, &allowed(false)).reason,
        Reason::InvalidRequest
    );
}

#[test]
fn b5_only_approval_classes_are_guarded() {
    assert!(class(ActionClass::Delete).is_guarded());
    for a in [Action::ReadLog, Action::AppendRecord, Action::CallTool] {
        assert!(!a.is_guarded());
        assert_eq!(Action::parse(a.as_str()), Some(a));
    }
}

#[test]
fn b6_engine_debug_names_the_hash_but_not_the_policy_text() {
    let e = reference();
    let s = format!("{e:?}");
    assert!(s.contains(&e.policy_set_hash()));
    assert!(!s.contains("permit"));
}

fn is_limit(r: Result<Engine, PolicyError>) -> bool {
    matches!(r, Err(PolicyError::Limit(_)))
}

fn padded(base: &str, total: usize) -> String {
    let mut s = base.to_string();
    s.push_str("\n// ");
    while s.len() < total - 1 {
        s.push('x');
    }
    s.push('\n');
    assert_eq!(s.len(), total);
    s
}

#[test]
fn b7_text_size_limits_at_the_edge() {
    let (d, kb) = (entropa_approvals::Directory::default, 1024);
    let ok = |s: &str, p: &str| Engine::new_bound(s, p, d());
    assert!(!is_limit(ok(&padded(SCHEMA, 64 * kb), POLICIES)));
    assert!(is_limit(ok(&padded(SCHEMA, 64 * kb + 1), POLICIES)));
    assert!(!is_limit(ok(SCHEMA, &padded(POLICIES, 256 * kb))));
    assert!(is_limit(ok(SCHEMA, &padded(POLICIES, 256 * kb + 1))));
}

#[test]
fn b8_policy_count_limit_at_the_edge() {
    let many = |n: usize| {
        (0..n)
            .map(|i| {
                format!(
                    "@id(\"p{i}\") permit(principal, action == Action::\"read_log\", resource);\n"
                )
            })
            .collect::<String>()
    };
    let load =
        |n: usize| Engine::new_bound(SCHEMA, &many(n), entropa_approvals::Directory::default());
    assert!(load(256).is_ok());
    assert!(is_limit(load(257)));
}
