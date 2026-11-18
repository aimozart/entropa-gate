//! EG1f: a fast sample of the DEV bars and the older clean sets for the mutation runs (every 6th secret case, every 5th clean case: seconds, not half a minute). Written after the green code (not red-first); the full bars are in eg1f_context.rs x4.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common_f;
use common_f::*;

#[test]
fn f1_a_sample_of_dev_f_keeps_the_bars() {
    let p = policy_of("eval_dev_f");
    let secrets: Vec<_> = cases("eval_dev_f", "eg_secrets.jsonl")
        .into_iter()
        .step_by(6)
        .collect();
    let clean: Vec<_> = cases("eval_dev_f", "eg_clean.jsonl")
        .into_iter()
        .step_by(5)
        .collect();
    let leaked = secrets.iter().filter(|c| leaks(c, v2(c, &p))).count();
    let blocked = clean.iter().filter(|c| blocks_clean(c, v2(c, &p))).count();
    assert_eq!(leaked, 0, "of {} sampled secret cases", secrets.len());
    assert!(
        blocked <= 1,
        "{blocked} of {} sampled clean cases blocked",
        clean.len()
    );
}

#[test]
fn f2_a_sample_of_the_older_clean_sets_gets_no_new_block() {
    for set in ["eval_dev_c", "eval_dev_d", "eval_dev_e"] {
        let p = policy_of(set);
        for c in cases(set, "eg_clean.jsonl").into_iter().step_by(5) {
            assert!(
                !(v1(&c, &p) != entropa_egress::decide::Action::Block
                    && v2(&c, &p) == entropa_egress::decide::Action::Block),
                "{set}: {}",
                c["id"]
            );
        }
    }
}

// ---- JSON bodies, attachments and headers (written after the code; the sealed sets carry requests as JSON fields) ----
use entropa_egress::decide::{Action, Attachment, Request};

fn req_json(body: &str) -> Request {
    Request {
        destination: "https://api.model.example/v1/chat".into(),
        body: body.as_bytes().to_vec(),
        body_is_json: true,
        attachments: vec![],
        headers: vec![],
    }
}
fn act(r: &Request) -> Action {
    let p = policy_of("eval_dev_f");
    entropa_egress::v2::decide_v2(r, &p, entropa_egress::policy::Tier::T1, &conv(), &Null).action
}

#[test]
fn f3_json_bodies_are_read_leaf_by_leaf_and_pairs_by_key() {
    // the quote characters inside a JSON string are escaped on the wire; the context scan must read the decoded text
    assert_eq!(
        act(&req_json(
            r#"{"msg": "please use password = \"Xk39fQ2zLp\" for the db"}"#
        )),
        Action::Block
    );
    assert_eq!(
        act(&req_json(
            r#"{"msg": "ALTER USER app PASSWORD 'island ember 42! harbor';"}"#
        )),
        Action::Block
    );
    assert_eq!(
        act(&req_json(
            r#"{"config": {"client_secret": "island ember 42! harbor"}}"#
        )),
        Action::Block
    );
    assert_eq!(
        act(&req_json(r#"{"items": [{"api_key": "Xk39fQ2zLpA9"}]}"#)),
        Action::Block
    );
    assert_eq!(
        act(&req_json(
            r#"{"msg": "Please summarise the retention clause.", "n": 3}"#
        )),
        Action::Allow
    );
    assert_eq!(
        act(&req_json(
            r#"{"msg": "the password policy requires twelve characters"}"#
        )),
        Action::Allow
    );
    assert_eq!(act(&req_json(r#"{"password": ""}"#)), Action::Allow);
    assert_eq!(
        act(&req_json("{not json password = \"Xk39fQ2zLp\"")),
        Action::Block
    );
}

#[test]
fn f4_headers_and_attachments_are_read_too() {
    let mut r = req_json(r#"{"msg": "hello"}"#);
    r.headers = vec![("Authorization".into(), "Bearer Xk39fQ2zLpA9bC".into())];
    assert_eq!(act(&r), Action::Block);
    let mut r = req_json(r#"{"msg": "hello"}"#);
    r.headers = vec![("Authorization".into(), "Bearer ${TOKEN}".into())];
    assert_ne!(act(&r), Action::Block);
    let mut r = req_json(r#"{"msg": "hello"}"#);
    r.attachments = vec![Attachment {
        name: "a".into(),
        mime: "text/plain".into(),
        bytes: b"db.password=Xk39fQ2zLp\n".to_vec(),
    }];
    assert_eq!(act(&r), Action::Block);
}
