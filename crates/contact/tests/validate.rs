//! Validation, sanitising and email building. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_contact::*;
use serde_json::json;

fn ok() -> serde_json::Value {
    json!({"name":"Jane Recruiter","email":"jane@example.com","reason":"Hiring inquiry","message":"Hello, we would like to talk.","website":""})
}

#[test]
fn v1_a_good_submission_is_accepted() {
    let c = validate(&ok()).unwrap();
    assert_eq!(c.name, "Jane Recruiter");
    assert_eq!(c.email, "jane@example.com");
    assert_eq!(c.reason, "Hiring inquiry");
}

#[test]
fn v2_the_honeypot_marks_spam() {
    let mut v = ok();
    v["website"] = json!("http://spam.example");
    assert_eq!(validate(&v), Err(Reject::Spam));
}

#[test]
fn v3_bad_fields_are_invalid() {
    for (k, bad) in [
        ("name", json!("")),
        ("name", json!("x".repeat(101))),
        ("name", json!("Jane\r\nBcc: victim@example.com")),
        ("email", json!("not-an-email")),
        ("email", json!("a b@example.com")),
        ("email", json!("jane@example.com\r\nBcc: x@example.com")),
        ("email", json!("jane@nodot")),
        ("message", json!("")),
        ("message", json!("x".repeat(5001))),
    ] {
        let mut v = ok();
        v[k] = bad.clone();
        assert_eq!(validate(&v), Err(Reject::Invalid), "{k}: {bad}");
    }
    assert_eq!(validate(&json!("text")), Err(Reject::Invalid));
    assert_eq!(validate(&json!({})), Err(Reject::Invalid));
}

#[test]
fn v4_the_reason_is_limited_to_a_short_clean_phrase() {
    let mut v = ok();
    v["reason"] = json!("bad\nreason");
    assert_eq!(validate(&v).unwrap().reason, "General");
    v["reason"] = json!("x".repeat(100));
    assert_eq!(validate(&v).unwrap().reason, "General");
    v.as_object_mut().unwrap().remove("reason");
    assert_eq!(validate(&v).unwrap().reason, "General");
}

#[test]
fn v5_the_email_text_carries_the_sender_without_header_injection() {
    let c = validate(&ok()).unwrap();
    let m = build_message(&c);
    assert_eq!(m.subject, "Entropa contact: Hiring inquiry");
    assert!(
        m.body.contains("Jane Recruiter")
            && m.body.contains("jane@example.com")
            && m.body.contains("Hello, we would like")
    );
    assert!(!m.subject.contains('\n') && !m.subject.contains('\r'));
    assert_eq!(m.reply_to, "jane@example.com");
}
