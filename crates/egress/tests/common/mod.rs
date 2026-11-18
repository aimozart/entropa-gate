//! Shared helpers: a recording sink, a failing sink, the dev policy and request builders. Synthetic canaries only.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::decide::{Conversation, Request};
use entropa_egress::policy::{sign_dev, DevHashVerifier, Policy};
use entropa_egress::record::{EvidenceRequest, RecordSink};
use std::cell::RefCell;

pub const KEY: &[u8] = b"dev-verifier-key-not-a-signature";
pub const DEST: &str = "https://api.model.example/v1/chat";
pub const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

pub struct Mem(pub RefCell<Vec<EvidenceRequest>>);
impl Mem {
    pub fn new() -> Mem {
        Mem(RefCell::new(vec![]))
    }
    pub fn last(&self) -> EvidenceRequest {
        self.0.borrow().last().cloned().unwrap()
    }
    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }
}
impl RecordSink for Mem {
    fn emit(&self, r: &EvidenceRequest) -> Result<(), String> {
        self.0.borrow_mut().push(r.clone());
        Ok(())
    }
}
pub struct Failing;
impl RecordSink for Failing {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        Err("disk full".into())
    }
}

pub fn policy_json() -> String {
    sign_dev(
        &entropa_egress::policy::template_json("api.model.example"),
        KEY,
    )
}
pub fn policy() -> Policy {
    Policy::parse(&policy_json(), &DevHashVerifier::new(KEY)).unwrap()
}
pub fn conv() -> Conversation {
    Conversation {
        key: b"conversation-key-0001".to_vec(),
        tail: String::new(),
        seen: vec![],
    }
}
pub fn text_req(body: &str) -> Request {
    Request {
        destination: DEST.into(),
        body: body.as_bytes().to_vec(),
        body_is_json: false,
        attachments: vec![],
        headers: vec![],
    }
}
pub fn json_req(body: &str) -> Request {
    Request {
        destination: DEST.into(),
        body: body.as_bytes().to_vec(),
        body_is_json: true,
        attachments: vec![],
        headers: vec![],
    }
}
