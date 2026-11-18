//! Test-plan rows E1-E3 (docs/ARCHITECTURE-APPROVALS.md section 10) and key ids.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::*;
use entropa_core::Probe;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("vectors/approval_v1.json");

fn class_of(s: &str) -> ActionClass {
    ActionClass::ALL
        .into_iter()
        .find(|c| c.as_str() == s)
        .unwrap_or_else(|| panic!("action class names: not yet implemented ({s})"))
}

#[test]
fn key_id_is_sixteen_hex_chars_of_blake3_over_the_key_bytes() {
    let k = Probe::spawn().pubkey_hex();
    let id = key_id(&k);
    assert_eq!(id.len(), 16, "key_id: not yet implemented");
    assert_eq!(
        id,
        hex::encode(&blake3::hash(&hex::decode(&k).unwrap()).as_bytes()[..8])
    );
}

#[test]
fn e1_golden_vectors_match_an_independent_implementation() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let rid = v["request_id"].as_str().unwrap();
    for case in v["cases"].as_array().unwrap() {
        let p = &case["params"];
        let opt = |k: &str| p[k].as_str().map(str::to_string);
        let event = match case["kind"].as_str().unwrap() {
            "request" => Event::request(
                p["actor"].as_str().unwrap(),
                p["ts"].as_u64().unwrap(),
                class_of(p["action_class"].as_str().unwrap()),
                p["subject_hash"].as_str().unwrap(),
                p["subject_ref"].as_str().unwrap(),
                p["valid_for_secs"].as_u64().unwrap(),
            ),
            "approve" => Event::approve(
                p["actor"].as_str().unwrap(),
                p["ts"].as_u64().unwrap(),
                rid,
                opt("on_behalf_of").as_deref(),
                opt("basis_hash").as_deref(),
            ),
            "deny" => Event::deny(
                p["actor"].as_str().unwrap(),
                p["ts"].as_u64().unwrap(),
                rid,
                ReasonCode::TooRisky,
                opt("on_behalf_of").as_deref(),
                opt("basis_hash").as_deref(),
            ),
            _ => Event::consume(p["actor"].as_str().unwrap(), p["ts"].as_u64().unwrap(), rid),
        };
        assert_eq!(
            event.request_id, rid,
            "request id derivation: not yet implemented"
        );
        assert_eq!(
            String::from_utf8(canonical_bytes(&event)).unwrap(),
            case["canonical"].as_str().unwrap(),
            "canonical_bytes: not yet implemented"
        );
        assert_eq!(
            hex::encode(signing_digest(&event)),
            case["digest_hex"].as_str().unwrap(),
            "signing_digest: not yet implemented"
        );
    }
}

#[test]
fn e1_every_event_type_round_trips_and_the_payload_is_canonical_json_with_the_signature() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", NOW, 86_400);
    let rid = req.event.request_id.clone();
    let all = [
        req,
        f.approve_by(&f.owner, &f.owner_id, &rid, NOW + 1),
        f.deny_by(&f.owner, &f.owner_id, &rid, NOW + 2),
        f.attest_approve(&rid, NOW + 3),
        f.consume_by_requester(&rid, NOW + 4),
    ];
    for e in all {
        let payload = must(encode(&e));
        assert_eq!(must(decode(&payload)), e);
        let v: Value = serde_json::from_str(&payload).unwrap();
        assert!(v["sig"].as_str().unwrap().len() > 100);
        // keys are sorted and there is no whitespace
        assert_eq!(payload, serde_json::to_string(&v).unwrap());
    }
}

#[test]
fn e2_malformed_payloads_are_rejected_without_echoing_the_value() {
    let f = fx();
    let good = must(encode(&f.request(ActionClass::Delete, "s1", NOW, 86_400)));
    let base: Value = serde_json::from_str(&good).unwrap();
    let secret = "secret value 123";
    let mut cases: Vec<(&str, Value)> = Vec::new();
    let mut c = base.clone();
    c["extra"] = json!(secret);
    cases.push(("unknown field", c));
    let mut c = base.clone();
    c["subject_hash"] = json!(base["subject_hash"].as_str().unwrap().to_uppercase());
    cases.push(("uppercase hex", c));
    let mut c = base.clone();
    c["subject_ref"] = json!(secret);
    cases.push(("token with spaces", c));
    let mut c = base.clone();
    c["subject_ref"] = json!("a".repeat(65));
    cases.push(("65-char token", c));
    let mut c = base.clone();
    c["v"] = json!(2);
    cases.push(("version 2", c));
    let mut c = base.clone();
    c.as_object_mut().unwrap().remove("sig");
    cases.push(("missing sig", c));
    let mut c = base.clone();
    c["valid_for_secs"] = json!(59);
    cases.push(("validity 59", c));
    let mut c = base.clone();
    c["valid_for_secs"] = json!(604_801);
    cases.push(("validity 604801", c));
    let mut c = base.clone();
    c["action_class"] = json!("wire_money");
    cases.push(("unknown action class", c));
    let mut c = base.clone();
    c["ts"] = json!("1700000000");
    cases.push(("ts as string", c));
    for (what, c) in cases {
        match decode(&c.to_string()) {
            Err(ApprovalError::Invalid(m)) => {
                assert!(!m.contains(secret) && !m.is_empty(), "{what}: message {m}")
            }
            Err(ApprovalError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
            Ok(_) => panic!("{what}: a malformed payload was accepted"),
        }
    }
    assert!(
        matches!(decode("not json"), Err(ApprovalError::Invalid(_))),
        "decode: {NOT_IMPLEMENTED}"
    );
}

#[test]
fn e3_the_signature_covers_every_field() {
    let f = fx();
    let req = f.request(ActionClass::Delete, "s1", NOW - 1000, 86_400);
    let rid = req.event.request_id.clone();
    let approve = f.approve_by(&f.owner, &f.owner_id, &rid, NOW - 500);
    let mut fields: Vec<(&str, Value)> = vec![
        ("ts", json!(NOW - 499)),
        ("actor", json!(f.requester_id)),
        ("request_id", json!(subject("other"))),
    ];
    let mut mutated = 0;
    for (field, new) in fields.drain(..) {
        let mut v: Value = serde_json::from_str(&must(encode(&approve))).unwrap();
        v[field] = new;
        let mut log = log_with(std::slice::from_ref(&req));
        log.append(
            &entropa_core::transparency_log::encode_record(
                &v.to_string(),
                Some("approval.approve"),
            )
            .unwrap(),
        );
        let state = replay(&log, &f.dir, NOW);
        assert!(
            state.rejected.iter().any(|r| r.index == 1),
            "tampering {field} must be rejected"
        );
        mutated += 1;
    }
    assert_eq!(mutated, 3);
}
