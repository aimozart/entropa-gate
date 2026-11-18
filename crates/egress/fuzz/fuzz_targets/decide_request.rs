#![no_main]
//! EG1 task 4: the whole decision on arbitrary bytes. `decide` catches a panic and blocks with `internal_error`, which would hide the defect
//! from libFuzzer, so the target asserts the reason is never `internal_error` (found by the sealed run of 2026-11-14: a byte index inside a
//! multibyte character) and that two runs of the same request agree (E2).
use entropa_egress::decide::{decide, Attachment, Conversation, Reason, Request};
use entropa_egress::policy::{sign_dev, template_json, DevHashVerifier, Policy, Tier};
use entropa_egress::record::{EvidenceRequest, RecordSink};
use libfuzzer_sys::fuzz_target;

const KEY: &[u8] = b"dev-verifier-key-not-a-signature";
struct Null;
impl RecordSink for Null {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        Ok(())
    }
}
fn policy() -> Policy {
    Policy::parse(&sign_dev(&template_json("api.model.example"), KEY), &DevHashVerifier::new(KEY)).expect("dev policy")
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let tier = [Tier::T1, Tier::T2, Tier::T3][usize::from(sel >> 4) % 3];
    let mut req = Request { destination: "https://api.model.example/v1/chat".into(), body: Vec::new(), body_is_json: false, attachments: vec![], headers: vec![] };
    let lossy = String::from_utf8_lossy(rest).to_string();
    match sel & 7 {
        0 => req.body = rest.to_vec(),
        1 => { req.body = rest.to_vec(); req.body_is_json = true; }
        2 => { req.body = b"hello".to_vec(); req.headers = vec![("x-note".into(), lossy)]; }
        3 => { req.body = b"hello".to_vec(); req.attachments = vec![Attachment { name: "a.txt".into(), mime: "text/plain".into(), bytes: rest.to_vec() }]; }
        4 => { req.body = format!("{{\"a\":{}}}", serde_str(&lossy)).into_bytes(); req.body_is_json = true; }
        5 => req.destination = lossy,
        _ => req.body = lossy.into_bytes(),
    }
    let conv = Conversation { key: b"fuzz-conversation-key".to_vec(), tail: String::new(), seen: vec![] };
    let p = policy();
    let a = decide(&req, &p, tier, &conv, &Null);
    assert_ne!(a.reason(), Reason::InternalError, "a panic was caught inside decide");
    let b = decide(&req, &p, tier, &conv, &Null);
    assert_eq!((a.action(), a.reason()), (b.action(), b.reason()), "not deterministic");
});

/// A JSON string literal of `s` without a dependency: escape quotes, backslashes and control characters.
fn serde_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}
