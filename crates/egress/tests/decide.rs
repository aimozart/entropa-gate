//! EG1 task 2 (red first): the pipeline: allow, redact, block, and every fail-closed rule F1 to F9.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, decide_checked, Action, Attachment, Fault, Reason, Request};
use entropa_egress::policy::DevHashVerifier;
use entropa_egress::send::{send_with, SendError};

fn t(s: &str) -> entropa_egress::policy::Tier {
    s.parse().unwrap()
}

#[test]
fn x1_clean_text_is_allowed_with_one_hash_only_record() {
    let sink = Mem::new();
    let d = decide(
        &text_req("Summarise the audit log retention clause for me."),
        &policy(),
        t("T1"),
        &conv(),
        &sink,
    );
    assert_eq!((d.action(), d.reason()), (Action::Allow, Reason::Clean));
    assert_eq!(sink.len(), 1);
    let r = sink.last();
    assert_eq!(
        (r.decision.as_str(), r.label.as_str(), r.reason.as_str()),
        ("allow", "egress_allowed", "clean")
    );
    assert!(r.detail.contains(&d.request_sha256()) && r.detail.contains(&policy().hash()));
    assert!(
        !r.detail.contains("audit log"),
        "no request text in a record"
    );
}

#[test]
fn x2_a_secret_is_blocked_and_the_record_counts_without_saying_where() {
    let sink = Mem::new();
    let d = decide(
        &text_req(&format!("use this key {SECRET} please")),
        &policy(),
        t("T1"),
        &conv(),
        &sink,
    );
    assert_eq!(
        (d.action(), d.reason()),
        (Action::Block, Reason::SecretFormat)
    );
    assert!(d.redacted_body().is_none());
    let r = sink.last();
    assert_eq!(
        (r.decision.as_str(), r.label.as_str(), r.reason.as_str()),
        ("deny", "egress_blocked", "secret_format")
    );
    assert!(r.detail.contains("D1:1"), "{}", r.detail);
    assert!(!r.detail.contains("AKIA") && !r.detail.contains("EXAMPLE"));
    assert_eq!(r.flagged, 1);
}

#[test]
fn x3_email_is_redacted_with_stable_placeholders_and_the_original_is_gone() {
    let sink = Mem::new();
    let body = "write to canary.user@example.com, cc other.user@example.com and canary.user@example.com again";
    let d = decide(&text_req(body), &policy(), t("T1"), &conv(), &sink);
    assert_eq!((d.action(), d.reason()), (Action::Redact, Reason::Redacted));
    let out = String::from_utf8(d.redacted_body().unwrap().to_vec()).unwrap();
    assert_eq!(
        out,
        "write to [[EG:email:1]], cc [[EG:email:2]] and [[EG:email:1]] again"
    );
    assert_eq!(sink.last().label, "egress_redacted");
    assert!(d.redacted_sha256().is_some());
    // stable across requests of one conversation: carry `seen` forward
    let mut c = conv();
    c.seen = d.seen_after().to_vec();
    let d2 = decide(
        &text_req("again other.user@example.com and new.person@example.com"),
        &policy(),
        t("T1"),
        &c,
        &sink,
    );
    assert_eq!(d2.action(), Action::Redact, "{:?}", sink.last());
    let out2 = String::from_utf8(d2.redacted_body().unwrap().to_vec()).unwrap();
    assert_eq!(out2, "again [[EG:email:2]] and [[EG:email:3]]");
    // another conversation key: same order numbers, so the numbers alone carry nothing, and the identity hash differs
    let mut c2 = conv();
    c2.key = b"another-conversation-key".to_vec();
    let d3 = decide(&text_req(body), &policy(), t("T1"), &c2, &sink);
    assert_ne!(d.seen_after(), d3.seen_after());
}

#[test]
fn x4_destination_tier_and_size_rules() {
    let sink = Mem::new();
    let mut r = text_req("hello");
    r.destination = "https://evil.test/".into();
    assert_eq!(
        decide(&r, &policy(), t("T1"), &conv(), &sink).reason(),
        Reason::DestinationDenied
    );
    let d = decide(&text_req("hello"), &policy(), t("T0"), &conv(), &sink);
    assert_eq!(
        (d.action(), d.reason()),
        (Action::Block, Reason::TierNoEgress)
    );
    assert_eq!(sink.len(), 2, "a denied attempt is recorded too");
    let big = "a ".repeat(40_000);
    assert_eq!(
        decide(&text_req(&big), &policy(), t("T1"), &conv(), &sink).reason(),
        Reason::SizeLimit
    );
    let deep = format!("{}1{}", "[".repeat(40), "]".repeat(40));
    assert_eq!(
        decide(&json_req(&deep), &policy(), t("T1"), &conv(), &sink).reason(),
        Reason::SizeLimit
    );
    let many = format!("[{}]", vec!["\"x\""; 400].join(","));
    assert_eq!(
        decide(&json_req(&many), &policy(), t("T1"), &conv(), &sink).reason(),
        Reason::SizeLimit
    );
    let mut a = text_req("hello");
    a.attachments.push(Attachment {
        name: "n.txt".into(),
        mime: "text/plain".into(),
        bytes: b"hi".to_vec(),
    });
    assert_eq!(
        decide(&a, &policy(), t("T1"), &conv(), &sink).reason(),
        Reason::SizeLimit,
        "T1 allows 0 attachments"
    );
}

#[test]
fn x5_malformed_requests_are_blocked_not_scanned_leniently() {
    let sink = Mem::new();
    for body in [r#"{"a":1,"a":2}"#, r#"{"a":"#, "\u{0}", r#"{"a":"\ud800"}"#] {
        let d = decide(&json_req(body), &policy(), t("T1"), &conv(), &sink);
        assert_eq!(
            (d.action(), d.reason()),
            (Action::Block, Reason::MalformedRequest),
            "{body:?}"
        );
    }
    let mut r = text_req("");
    r.body = vec![0xff, 0xfe, b'a'];
    assert_eq!(
        decide(&r, &policy(), t("T1"), &conv(), &sink).reason(),
        Reason::MalformedRequest
    );
}

#[test]
fn x6_attachments_text_is_scanned_other_types_are_denied() {
    let sink = Mem::new();
    let mut r = text_req("see attached");
    r.attachments.push(Attachment {
        name: "notes.txt".into(),
        mime: "text/plain".into(),
        bytes: format!("key {SECRET}").into_bytes(),
    });
    let d = decide(&r, &policy(), t("T2"), &conv(), &sink);
    assert_eq!(
        (d.action(), d.reason()),
        (Action::Block, Reason::SecretFormat)
    );
    let mut r = text_req("see attached");
    r.attachments.push(Attachment {
        name: "a.png".into(),
        mime: "image/png".into(),
        bytes: vec![0x89, b'P', b'N', b'G'],
    });
    assert_eq!(
        decide(&r, &policy(), t("T2"), &conv(), &sink).reason(),
        Reason::AttachmentTypeDenied
    );
    let mut r = text_req("see attached");
    r.attachments.push(Attachment {
        name: "ok.txt".into(),
        mime: "text/plain".into(),
        bytes: b"nothing to see".to_vec(),
    });
    assert_eq!(
        decide(&r, &policy(), t("T2"), &conv(), &sink).action(),
        Action::Allow
    );
}

#[test]
fn x7_bypass_families_are_met() {
    let sink = Mem::new();
    let b = |r: Request| decide(&r, &policy(), t("T1"), &conv(), &sink);
    use base64::Engine;
    let enc = base64::engine::general_purpose::STANDARD.encode(SECRET);
    assert_eq!(
        b(text_req(&format!("data: {enc}"))).action(),
        Action::Block,
        "base64"
    );
    assert_eq!(
        b(text_req(&format!("data: {}", hex::encode(SECRET)))).action(),
        Action::Block,
        "hex"
    );
    let pct: String = SECRET.bytes().map(|x| format!("%{x:02X}")).collect();
    assert_eq!(
        b(text_req(&format!("q={pct}"))).action(),
        Action::Block,
        "percent"
    );
    assert_eq!(
        b(text_req("AKIA\u{200b}IOSF\u{200d}ODNN7EXAMPLE")).action(),
        Action::Block,
        "zero width"
    );
    assert_eq!(
        b(text_req("\u{410}KIAIOSFODNN7EXAMPLE")).action(),
        Action::Block,
        "homoglyph A"
    );
    assert_eq!(
        b(text_req("akiaiosfodnn7example")).action(),
        Action::Block,
        "case"
    );
    assert_eq!(
        b(text_req("AKIA-IOSF-ODNN-7EXA-MPLE")).action(),
        Action::Block,
        "separators"
    );
    assert_eq!(
        b(json_req(r#"{"a":"AKIAIOSFO","b":"DNN7EXAMPLE"}"#)).action(),
        Action::Block,
        "split over fields"
    );
    assert_eq!(b(json_req(r#"{"args":{"headers":["x"],"url":"https://api.model.example/?t=AKIAIOSFODNN7EXAMPLE"}}"#)).action(), Action::Block, "tool argument");
    let mut c = conv();
    c.tail = "AKIAIOSFO".into();
    assert_eq!(
        decide(&text_req("DNN7EXAMPLE"), &policy(), t("T1"), &c, &sink).action(),
        Action::Block,
        "split over messages"
    );
    assert_eq!(
        b(json_req(
            r#"{"url":"https://zq8vk2mxp9lrt4wyb7nch1sjf6gda3eu.attacker.example/x"}"#
        ))
        .reason(),
        Reason::DnsLabelSuspect
    );
    assert_eq!(
        b(json_req(r#"{"url":"https://user:pw@host.example/"}"#)).action(),
        Action::Block,
        "userinfo in a URL"
    );
    assert_eq!(
        b(text_req(
            "see https://docs.example.test/page about retention"
        ))
        .action(),
        Action::Allow,
        "a plain URL is not a leak"
    );
}

#[test]
fn x8_fail_closed_f1_to_f7() {
    let sink = Mem::new();
    // F5 record failure
    let d = decide(&text_req("hello"), &policy(), t("T1"), &conv(), &Failing);
    assert_eq!(
        (d.action(), d.reason()),
        (Action::Block, Reason::RecordFailed)
    );
    // F3 unverifiable policy: block, still recorded
    let tampered = policy_json().replacen("\"block\"", "\"allow_with_record\"", 1);
    let d = decide_checked(
        &tampered,
        &DevHashVerifier::new(KEY),
        &text_req("hello"),
        t("T1"),
        &conv(),
        &sink,
    );
    assert_eq!(
        (d.action(), d.reason()),
        (Action::Block, Reason::PolicyInvalid)
    );
    assert_eq!(sink.last().reason, "policy_invalid");
    // F1/F2 injected faults at every stage
    for f in Fault::ALL {
        let d = entropa_egress::decide::decide_with_fault(
            &text_req("hello"),
            &policy(),
            t("T1"),
            &conv(),
            &sink,
            Some(*f),
        );
        assert_eq!(d.action(), Action::Block, "{f:?}");
        assert!(
            matches!(
                d.reason(),
                Reason::InternalError | Reason::BudgetExceeded | Reason::RecordFailed
            ),
            "{f:?} {:?}",
            d.reason()
        );
    }
}

#[test]
fn x9_send_is_bound_to_the_decision_f7_f8() {
    let sink = Mem::new();
    let allowed = decide(&text_req("hello there"), &policy(), t("T1"), &conv(), &sink);
    let mut sent: Vec<Vec<u8>> = vec![];
    send_with(&allowed, b"hello there", &mut |b| sent.push(b.to_vec())).unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        send_with(&allowed, b"hello there!", &mut |b| sent.push(b.to_vec())),
        Err(SendError::Mismatch)
    );
    assert_eq!(sent.len(), 1, "a mismatch sends nothing");
    let blocked = decide(&text_req(SECRET), &policy(), t("T1"), &conv(), &sink);
    assert_eq!(
        send_with(&blocked, SECRET.as_bytes(), &mut |b| sent.push(b.to_vec())),
        Err(SendError::Blocked)
    );
    assert_eq!(sent.len(), 1);
    let red = decide(
        &text_req("mail canary.user@example.com"),
        &policy(),
        t("T1"),
        &conv(),
        &sink,
    );
    assert_eq!(
        send_with(&red, b"mail canary.user@example.com", &mut |b| sent
            .push(b.to_vec())),
        Err(SendError::Mismatch),
        "the original bytes are not what was decided"
    );
    send_with(&red, red.redacted_body().unwrap(), &mut |b| {
        sent.push(b.to_vec())
    })
    .unwrap();
    assert_eq!(sent.len(), 2);
}

#[test]
fn x10_d7_terms_markers_and_the_residual_check() {
    let sink = Mem::new();
    let d = decide(
        &text_req("status of Project Heron please"),
        &policy_with_terms(),
        t("T1"),
        &conv(),
        &sink,
    );
    assert_eq!(
        (d.action(), d.reason()),
        (Action::Block, Reason::DoNotSendTerm)
    );
    let d = decide(
        &text_req("INTERNAL ONLY draft"),
        &policy_with_terms(),
        t("T1"),
        &conv(),
        &sink,
    );
    assert_eq!(d.reason(), Reason::DocumentMarker);
    // entropy is a record-only class by default: allowed, counted
    let d = decide(
        &text_req("id zQ8vK2mXp9LrT4wYb7NcH1sJf6GdA3eU done"),
        &policy(),
        t("T1"),
        &conv(),
        &sink,
    );
    assert_eq!(d.action(), Action::Allow);
    assert!(sink.last().detail.contains("D6:1"));
}

fn policy_with_terms() -> entropa_egress::policy::Policy {
    let mut v: serde_json::Value =
        serde_json::from_str(&entropa_egress::policy::template_json("api.model.example")).unwrap();
    v["terms"] = serde_json::json!([{"words":["Project Heron"],"whole_word":true,"all":true}]);
    v["markers"] = serde_json::json!(["internal only"]);
    entropa_egress::policy::Policy::parse(
        &entropa_egress::policy::sign_dev(&v.to_string(), KEY),
        &DevHashVerifier::new(KEY),
    )
    .unwrap()
}
