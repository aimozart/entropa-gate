//! Test-plan rows C1, C2, C3, C9, C10, C11 (docs/ARCHITECTURE-CEDAR.md section 11).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::{ActionClass, BlockReason};
use entropa_policy::*;

#[test]
fn c1_the_reference_schema_and_policies_load_and_validate() {
    let e = reference();
    assert_eq!(
        e.policy_set_hash().len(),
        64,
        "policy_set_hash: {NOT_IMPLEMENTED}"
    );
}

#[test]
fn c1_bad_inputs_are_rejected_with_the_right_kind_of_error() {
    let check = |schema: &str, policies: &str, want: &str| match Engine::new(schema, policies) {
        Err(PolicyError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(PolicyError::Parse(_)) if want == "parse" => {}
        Err(PolicyError::Validation(_)) if want == "validation" => {}
        Err(PolicyError::Limit(_)) if want == "limit" => {}
        other => panic!("expected {want}, got {:?}", other.map(|_| "engine")),
    };
    check(SCHEMA, "permit(principal, action, resource", "parse");
    check("entity {{{", POLICIES, "parse");
    check(
        SCHEMA,
        r#"permit(principal, action == Action::"wire_money", resource);"#,
        "validation",
    );
    check(
        SCHEMA,
        r#"@id("has a space") permit(principal, action == Action::"read_log", resource);"#,
        "validation",
    );
    check(
        SCHEMA,
        r#"permit(principal, action == Action::"read_log", resource) when { principal.nonexistent == "x" };"#,
        "validation",
    );
    check(SCHEMA, &"// padding\n".repeat(30_000), "limit");
    let many: String = (0..257)
        .map(|i| {
            format!("@id(\"p{i}\") permit(principal, action == Action::\"read_log\", resource);\n")
        })
        .collect();
    check(SCHEMA, &many, "limit");
}

#[test]
fn c1_an_empty_policy_set_loads_and_denies_everything() {
    let e = closed();
    for a in [
        Action::ReadLog,
        Action::AppendRecord,
        class(ActionClass::Direction),
    ] {
        let d = decide(&e, &req(a, RoleName::Human), &allowed(false));
        assert_eq!((d.outcome, d.reason), (Outcome::Deny, Reason::CedarDeny));
    }
}

#[test]
fn c2_default_deny_and_forbid_beats_permit() {
    let e = load(
        SCHEMA,
        r#"
        @id("permit-read") permit(principal, action == Action::"read_log", resource);
        @id("forbid-ai-read") forbid(principal, action == Action::"read_log", resource) when { principal.role == "ai" };
    "#,
    );
    let human = decide(
        &e,
        &req(Action::ReadLog, RoleName::Human),
        &blocked(BlockReason::NoRequest),
    );
    assert_eq!(
        (human.outcome, human.cedar),
        (Outcome::Allow, Some(Outcome::Allow))
    );
    assert_eq!(human.determining, vec!["permit-read".to_string()]);
    let ai = decide(
        &e,
        &req(Action::ReadLog, RoleName::Ai),
        &blocked(BlockReason::NoRequest),
    );
    assert_eq!((ai.outcome, ai.reason), (Outcome::Deny, Reason::CedarDeny));
    assert_eq!(ai.determining, vec!["forbid-ai-read".to_string()]);
    // no matching permit at all
    let none = decide(
        &e,
        &req(Action::AppendRecord, RoleName::Human),
        &blocked(BlockReason::NoRequest),
    );
    assert_eq!(
        (none.outcome, none.reason),
        (Outcome::Deny, Reason::CedarDeny)
    );
}

#[test]
fn c3_a_policy_that_errors_fails_closed_even_when_another_permit_matches() {
    let e = load(
        SCHEMA,
        r#"
        @id("fine") permit(principal, action == Action::"read_log", resource);
        @id("overflow") permit(principal, action, resource) when { context.now * 9223372036854775807 > 0 };
    "#,
    );
    let d = decide(
        &e,
        &req(Action::ReadLog, RoleName::Human),
        &blocked(BlockReason::NoRequest),
    );
    assert_eq!((d.outcome, d.reason), (Outcome::Deny, Reason::PolicyError));
    assert!(
        d.error_policies.contains(&"overflow".to_string()),
        "{:?}",
        d.error_policies
    );
}

#[test]
fn c9_decisions_are_deterministic_and_the_hash_follows_the_policy_text() {
    let e = reference();
    let r = req(class(ActionClass::Deploy), RoleName::Ai);
    let g = allowed(false);
    assert_eq!(decide(&e, &r, &g), decide(&e, &r, &g));
    let changed = load(SCHEMA, &format!("{POLICIES}\n// one more comment\n"));
    assert_ne!(e.policy_set_hash(), changed.policy_set_hash());
    assert_eq!(e.policy_set_hash(), reference().policy_set_hash());
}

#[test]
fn c10_hostile_ids_are_denied_without_panic_or_echo() {
    let e = reference();
    let long = "a".repeat(10_000);
    let hostile = [
        "x\"; permit(principal, action, resource); //".to_string(),
        "ab\\\"cd".to_string(),
        "\u{0}\u{0}".to_string(),
        "ünïcödé-ïd-1234".to_string(),
        long,
        String::new(),
    ];
    for h in &hostile {
        let mut r = req(Action::ReadLog, RoleName::Human);
        r.principal = h.clone();
        let d = decide(&e, &r, &blocked(BlockReason::NoRequest));
        assert_eq!(
            (d.outcome, d.reason),
            (Outcome::Deny, Reason::InvalidRequest),
            "principal {:?}",
            h.chars().take(20).collect::<String>()
        );
        let mut r = req(Action::ReadLog, RoleName::Human);
        r.subject_kind = h.clone();
        assert_eq!(
            decide(&e, &r, &blocked(BlockReason::NoRequest)).reason,
            Reason::InvalidRequest
        );
        let mut r = req(Action::ReadLog, RoleName::Human);
        r.subject_hash = h.clone();
        assert_eq!(
            decide(&e, &r, &blocked(BlockReason::NoRequest)).reason,
            Reason::InvalidRequest
        );
    }
    // the engine still works afterwards
    assert_eq!(
        decide(
            &e,
            &req(Action::ReadLog, RoleName::Human),
            &blocked(BlockReason::NoRequest)
        )
        .outcome,
        Outcome::Allow
    );
}

#[test]
fn c11_observe_mode_computes_the_same_decision_but_marks_it_unenforced() {
    let e = reference();
    let r = req(class(ActionClass::Delete), RoleName::Ai);
    let enforce = e.decide(&r, &allowed(false), Mode::Enforce);
    let observe = e.decide(&r, &allowed(false), Mode::Observe);
    assert!(
        enforce.reason != Reason::NotImplemented,
        "decide: {NOT_IMPLEMENTED}"
    );
    assert_eq!(
        (enforce.outcome, enforce.reason),
        (observe.outcome, observe.reason)
    );
    assert_eq!((enforce.enforced, observe.enforced), (true, false));
}
