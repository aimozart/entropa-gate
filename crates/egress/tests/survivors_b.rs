//! EG1b mutation triage, batch B: every limit of the default policy at its exact boundary (one under, at, one over). Limits come from the template
//! (T1: 64 KiB body, depth 8, 256 fields, no attachments; T2: 256 KiB, 16, 1024, 4 attachments of up to 1 MiB; tail 4096). The SEMANTICS pinned here are the
//! engine's, written down for review: depth and field counts include the root value and the innermost scalar (so a depth limit of 8 allows 7 nested
//! containers around a scalar, and a field limit of 256 allows an array of 255 elements, 256 values in all).
//! Not testable by input (argued in a stage record (not published)): `Budget::take` comparison at equality and `-=` -> `+=`: the budget is 24 x input + 64 KiB while the views
//! of one request cost about 8 x input at most, so no input can reach it; the injected-fault test (budget 0) covers the error path.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action, Attachment, Conversation, Reason, Request};
use entropa_egress::policy::Tier;

fn run(req: &Request, t: Tier) -> (Action, Reason) {
    let d = decide(req, &policy(), t, &conv(), &Mem::new());
    (d.action(), d.reason())
}
fn words(n: usize) -> String {
    // n bytes of harmless text: "a a a a ..."
    let mut s = "a ".repeat(n / 2);
    if n % 2 == 1 {
        s.push('a');
    }
    s
}
fn nested(k: usize) -> String {
    format!("{}1{}", "[".repeat(k), "]".repeat(k))
}
fn att(n: usize) -> Attachment {
    Attachment {
        name: "a.txt".into(),
        mime: "text/plain".into(),
        bytes: words(n).into_bytes(),
    }
}

#[test]
fn b1_the_body_limit_is_exact() {
    assert_eq!(
        run(&text_req(&words(65_535)), Tier::T1),
        (Action::Allow, Reason::Clean)
    );
    assert_eq!(
        run(&text_req(&words(65_536)), Tier::T1),
        (Action::Allow, Reason::Clean),
        "exactly 64 KiB is allowed"
    );
    assert_eq!(
        run(&text_req(&words(65_537)), Tier::T1),
        (Action::Block, Reason::SizeLimit)
    );
    // T2 has a larger limit
    assert_eq!(
        run(&text_req(&words(262_144)), Tier::T2),
        (Action::Allow, Reason::Clean)
    );
    assert_eq!(
        run(&text_req(&words(262_145)), Tier::T2),
        (Action::Block, Reason::SizeLimit)
    );
}

#[test]
fn b2_the_depth_limit_is_exact() {
    assert_eq!(
        run(&json_req(&nested(7)), Tier::T1),
        (Action::Allow, Reason::Clean),
        "7 containers around a scalar: depth 8"
    );
    assert_eq!(
        run(&json_req(&nested(8)), Tier::T1),
        (Action::Block, Reason::SizeLimit),
        "8 containers: depth 9"
    );
    let obj = |k: usize| format!("{}1{}", "{\"a\":".repeat(k), "}".repeat(k));
    assert_eq!(
        run(&json_req(&obj(7)), Tier::T1),
        (Action::Allow, Reason::Clean)
    );
    assert_eq!(
        run(&json_req(&obj(8)), Tier::T1),
        (Action::Block, Reason::SizeLimit)
    );
    // T2 allows 16 levels
    assert_eq!(
        run(&json_req(&nested(15)), Tier::T2),
        (Action::Allow, Reason::Clean)
    );
    assert_eq!(
        run(&json_req(&nested(16)), Tier::T2),
        (Action::Block, Reason::SizeLimit)
    );
    // a deep request must be refused whatever its width (the depth of a child is the parent's plus one)
    assert_eq!(
        run(
            &json_req(&format!("[{},{}]", nested(7), nested(7))),
            Tier::T1
        ),
        (Action::Block, Reason::SizeLimit),
        "a root plus 7 nested containers is depth 9"
    );
}

#[test]
fn b3_the_field_limit_is_exact() {
    let arr = |n: usize| format!("[{}]", vec!["1"; n].join(","));
    assert_eq!(
        run(&json_req(&arr(255)), Tier::T1),
        (Action::Allow, Reason::Clean),
        "the root and 255 elements are 256 values"
    );
    assert_eq!(
        run(&json_req(&arr(256)), Tier::T1),
        (Action::Block, Reason::SizeLimit)
    );
    assert_eq!(
        run(&json_req(&arr(1023)), Tier::T2),
        (Action::Allow, Reason::Clean)
    );
    assert_eq!(
        run(&json_req(&arr(1024)), Tier::T2),
        (Action::Block, Reason::SizeLimit)
    );
}

#[test]
fn b4_the_attachment_count_and_size_limits_are_exact() {
    let mut four = text_req("hello");
    four.attachments = (0..4).map(|_| att(100)).collect();
    assert_eq!(run(&four, Tier::T2), (Action::Allow, Reason::Clean));
    four.attachments.push(att(100));
    assert_eq!(
        run(&four, Tier::T2),
        (Action::Block, Reason::SizeLimit),
        "5 attachments at T2"
    );
    let mut one = text_req("hello");
    one.attachments = vec![att(1_048_576)];
    assert_eq!(
        run(&one, Tier::T2),
        (Action::Allow, Reason::Clean),
        "exactly 1 MiB"
    );
    one.attachments = vec![att(1_048_577)];
    assert_eq!(run(&one, Tier::T2), (Action::Block, Reason::SizeLimit));
    // T1 allows none at all
    let mut t1 = text_req("hello");
    t1.attachments = vec![att(10)];
    assert_eq!(run(&t1, Tier::T1), (Action::Block, Reason::SizeLimit));
}

#[test]
fn b5_a_long_conversation_tail_with_a_tiny_body_is_still_a_clean_request() {
    // the tail counts towards the scan budget with a plus sign: a tiny body and a 3,000-byte tail must not underflow the arithmetic
    let c = Conversation {
        key: b"conversation-key-0001".to_vec(),
        tail: words(3000),
        seen: vec![],
    };
    let d = decide(&text_req("hi"), &policy(), Tier::T1, &c, &Mem::new());
    assert_eq!((d.action(), d.reason()), (Action::Allow, Reason::Clean));
    // a tail longer than its limit is clipped, not refused
    let c = Conversation {
        key: b"conversation-key-0001".to_vec(),
        tail: words(20_000),
        seen: vec![],
    };
    let d = decide(&text_req("hi"), &policy(), Tier::T1, &c, &Mem::new());
    assert_eq!((d.action(), d.reason()), (Action::Allow, Reason::Clean));
}

#[test]
fn b6_an_exhausted_scan_budget_is_a_block_with_its_own_reason() {
    use entropa_egress::decide::{decide_with_fault, Fault};
    let d = decide_with_fault(
        &text_req("hello world"),
        &policy(),
        Tier::T1,
        &conv(),
        &Mem::new(),
        Some(Fault::Budget),
    );
    assert_eq!(
        (d.action(), d.reason()),
        (Action::Block, Reason::BudgetExceeded),
        "the budget fault must end in budget_exceeded, not in another reason or an allow"
    );
}
