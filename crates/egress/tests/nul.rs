//! EG1b: a NUL byte anywhere in the canonical request is refused as `malformed_request` (EG0 section 4, step 1). The sealed run of 2026-11-14 allowed
//! 25 of 25 NUL cases: the check looked at the raw body bytes only, but a JSON string reaches the engine as the escape `\u0000`, which only
//! becomes a NUL after parsing. Every place text enters the request is tested here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action, Attachment, Reason, Request};
use entropa_egress::policy::Tier;

fn run(req: &Request) -> (Action, Reason) {
    run_at(req, Tier::T1)
}
fn run_at(req: &Request, tier: Tier) -> (Action, Reason) {
    let d = decide(req, &policy(), tier, &conv(), &Mem::new());
    (d.action(), d.reason())
}

#[test]
fn n1_a_json_escaped_nul_in_a_string_value_is_refused() {
    for body in [
        r#"{"note":"hello\u0000world"}"#,
        r#"{"note":"\u0000"}"#,
        r#"{"a":["x","y\u0000"]}"#,
        r#"{"a":{"b":"c\u0000d"}}"#,
    ] {
        assert_eq!(
            run(&json_req(body)),
            (Action::Block, Reason::MalformedRequest),
            "{body}"
        );
    }
}

#[test]
fn n2_a_json_escaped_nul_in_a_key_is_refused() {
    assert_eq!(
        run(&json_req(r#"{"ke\u0000y":"v"}"#)),
        (Action::Block, Reason::MalformedRequest)
    );
}

#[test]
fn n3_a_raw_nul_in_a_plain_body_header_or_attachment_is_refused() {
    assert_eq!(
        run(&text_req("a\u{0}b")),
        (Action::Block, Reason::MalformedRequest)
    );
    let mut r = text_req("hello");
    r.headers = vec![("x-note".into(), "a\u{0}b".into())];
    assert_eq!(run(&r), (Action::Block, Reason::MalformedRequest));
    let mut r = text_req("hello");
    r.attachments = vec![Attachment {
        name: "n.txt".into(),
        mime: "text/plain".into(),
        bytes: b"a\0b".to_vec(),
    }];
    // T1 allows no attachments at all, so the attachment case runs at T3 (and its control without NUL must be allowed there)
    assert_eq!(
        run_at(&r, Tier::T3),
        (Action::Block, Reason::MalformedRequest)
    );
    r.attachments[0].bytes = b"a b".to_vec();
    assert_eq!(run_at(&r, Tier::T3).0, Action::Allow);
}

#[test]
fn n4_the_same_text_without_a_nul_is_allowed() {
    // the control: the refusal is about NUL, not about the shape of these requests
    for body in [r#"{"note":"hello world"}"#, r#"{"a":["x","y"]}"#] {
        assert_eq!(run(&json_req(body)).0, Action::Allow, "{body}");
    }
}
