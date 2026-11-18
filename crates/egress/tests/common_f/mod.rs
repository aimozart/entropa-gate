//! Shared helpers for the EG1f tests: load the DEV case files, build requests like the runner does, run the v1 and v2 pipelines, count leaks and false blocks.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::decide::{decide, Action, Conversation, Request};
use entropa_egress::eval::{load_policy, policy_from_extra};
use entropa_egress::policy::{Policy, Tier};
use entropa_egress::record::{EvidenceRequest, RecordSink};
use entropa_egress::v2::decide_v2;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct Null;
impl RecordSink for Null {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        Ok(())
    }
}

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
pub fn dir(name: &str) -> PathBuf {
    root().join("crates/egress").join(name)
}
pub fn policy_of(set: &str) -> Policy {
    let extra: Value = serde_json::from_str(
        &std::fs::read_to_string(dir(set).join("eg_policy_extra.json")).unwrap(),
    )
    .unwrap();
    load_policy(&policy_from_extra(&extra)).unwrap()
}
pub fn cases(set: &str, file: &str) -> Vec<Value> {
    std::fs::read_to_string(dir(set).join(file))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
pub fn request(c: &Value) -> Request {
    let body = match c.get("body_hex").and_then(Value::as_str) {
        Some(h) => hex::decode(h).unwrap(),
        None => c["body"].as_str().unwrap_or("").as_bytes().to_vec(),
    };
    Request {
        destination: c
            .get("destination")
            .and_then(Value::as_str)
            .unwrap_or("https://api.model.example/v1/chat")
            .to_string(),
        body,
        body_is_json: c
            .get("body_is_json")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        attachments: vec![],
        headers: vec![],
    }
}
pub fn conv() -> Conversation {
    Conversation {
        key: b"eval-conversation-key".to_vec(),
        tail: String::new(),
        seen: vec![],
    }
}
pub fn tier(c: &Value) -> Tier {
    c.get("tier")
        .and_then(Value::as_str)
        .unwrap_or("T1")
        .parse()
        .unwrap()
}
pub fn v1(c: &Value, p: &Policy) -> Action {
    decide(&request(c), p, tier(c), &conv(), &Null).action()
}
pub fn v2(c: &Value, p: &Policy) -> Action {
    decide_v2(&request(c), p, tier(c), &conv(), &Null).action
}
/// A secret case leaks when the action is not Block and the planted value is still recoverable from what would be sent (the runner's rule, simplified: no redaction hides a planted secret).
pub fn leaks(c: &Value, a: Action) -> bool {
    c["expect"] == "no_leak" && a != Action::Block
}
pub fn blocks_clean(c: &Value, a: Action) -> bool {
    c["expect"] == "allow" && a == Action::Block
}
