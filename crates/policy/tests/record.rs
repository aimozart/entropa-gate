//! Test-plan row C8: the decision record (section 7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::{ActionClass, BlockReason};
use entropa_core::transparency_log::{decode_record, verify_receipt, TransparencyLog};
use entropa_core::Probe;
use entropa_policy::*;
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/policy_decision_v1.json");

fn decision(
    cedar: Option<Outcome>,
    determining: &[&str],
    state: &str,
    attested: bool,
    outcome: Outcome,
    reason: Reason,
    enforced: bool,
) -> Decision {
    Decision {
        outcome,
        cedar,
        determining: determining.iter().map(|s| s.to_string()).collect(),
        error_policies: vec![],
        reason,
        enforced,
        approval_state: state.into(),
        approval_attested: attested,
    }
}

#[test]
fn c8_golden_vectors_match_an_independent_implementation() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let fixed = &v["fixed"];
    for case in v["cases"].as_array().unwrap() {
        let p = &case["params"];
        let action = match p["action"].as_str().unwrap() {
            "delete" => class(ActionClass::Delete),
            "deploy" => class(ActionClass::Deploy),
            other => panic!("golden vector uses an action the test does not know: {other}"),
        };
        let mut r = req(action, RoleName::Human);
        r.principal = fixed["principal"].as_str().unwrap().into();
        r.subject_hash = fixed["subject_hash"].as_str().unwrap().into();
        let cedar = if p["cedar"] == "allow" {
            Some(Outcome::Allow)
        } else {
            Some(Outcome::Deny)
        };
        let outcome = if p["outcome"] == "allow" {
            Outcome::Allow
        } else {
            Outcome::Deny
        };
        let reason = match p["reason"].as_str().unwrap() {
            "allowed" => Reason::Allowed,
            "gate_pending" => Reason::GateBlocked(BlockReason::Pending),
            other => panic!("unknown reason {other}"),
        };
        let det: Vec<&str> = p["determining"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        let d = decision(
            cedar,
            &det,
            p["approval_state"].as_str().unwrap(),
            p["approval_attested"].as_bool().unwrap(),
            outcome,
            reason,
            p["enforced"].as_bool().unwrap(),
        );
        let canon = record_canonical_bytes(
            &r,
            &d,
            fixed["policy_set_hash"].as_str().unwrap(),
            fixed["ts"].as_u64().unwrap(),
            fixed["actor"].as_str().unwrap(),
        );
        assert_eq!(
            String::from_utf8(canon.clone()).unwrap(),
            case["canonical"].as_str().unwrap(),
            "record_canonical_bytes: {NOT_IMPLEMENTED}"
        );
        assert_eq!(
            hex::encode(record_digest(&canon)),
            case["digest_hex"].as_str().unwrap(),
            "record_digest: {NOT_IMPLEMENTED}"
        );
    }
}

#[test]
fn c8_a_signed_record_round_trips_lands_in_the_log_and_verifies_with_a_receipt() {
    let signer = Probe::spawn();
    let e = reference();
    let r = req(class(ActionClass::Deploy), RoleName::Ai);
    let d = decide(&e, &r, &allowed(false));
    let rec = sign_record(&signer, ACTOR, &r, &d, &e.policy_set_hash(), NOW)
        .unwrap_or_else(|err| panic!("sign_record: {err:?}"));
    assert_eq!(decode_record_checked(&rec.payload), rec);
    let mut log = TransparencyLog::new();
    let idx = append_record(&mut log, &rec).unwrap_or_else(|err| panic!("append_record: {err:?}"));
    let head = log.checkpoint(&signer, NOW);
    let receipt = log.receipt(idx, &head).unwrap();
    assert!(verify_receipt(&receipt, &signer.pubkey_hex()));
    let (payload, label) = decode_record(&receipt.record).unwrap();
    assert_eq!(label.as_deref(), Some("policy.decision"));
    assert_eq!(payload, rec.payload);
}

fn decode_checked_inner(payload: &str) -> Result<DecisionRecord, PolicyError> {
    entropa_policy::decode_record(payload)
}
fn decode_record_checked(payload: &str) -> DecisionRecord {
    match decode_checked_inner(payload) {
        Ok(r) => r,
        Err(PolicyError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => panic!("decode failed: {e:?}"),
    }
}
#[test]
fn c8_the_decoder_is_strict_and_the_record_holds_no_free_text() {
    let signer = Probe::spawn();
    let e = reference();
    let r = req(class(ActionClass::Deploy), RoleName::Ai);
    let d = decide(&e, &r, &allowed(false));
    let rec = sign_record(&signer, ACTOR, &r, &d, &e.policy_set_hash(), NOW)
        .unwrap_or_else(|err| panic!("sign_record: {err:?}"));
    let base: Value = serde_json::from_str(&rec.payload).unwrap();
    for (what, mutate) in [
        (
            "unknown field",
            Box::new(|v: &mut Value| v["note"] = Value::String("secret value 123".into()))
                as Box<dyn Fn(&mut Value)>,
        ),
        (
            "free text in a policy id",
            Box::new(|v: &mut Value| v["determining"] = serde_json::json!(["has a space"])),
        ),
        (
            "version 2",
            Box::new(|v: &mut Value| v["v"] = serde_json::json!(2)),
        ),
        (
            "missing sig",
            Box::new(|v: &mut Value| {
                v.as_object_mut().unwrap().remove("sig");
            }),
        ),
        (
            "uppercase hash",
            Box::new(|v: &mut Value| {
                v["subject_hash"] =
                    Value::String(v["subject_hash"].as_str().unwrap().to_uppercase())
            }),
        ),
    ] {
        let mut v = base.clone();
        mutate(&mut v);
        match entropa_policy::decode_record(&v.to_string()) {
            Err(PolicyError::Invalid(m)) => {
                assert!(!m.contains("secret value 123"), "{what}: echoed the value")
            }
            Err(PolicyError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
            other => panic!("{what}: accepted or wrong error: {other:?}"),
        }
    }
}
