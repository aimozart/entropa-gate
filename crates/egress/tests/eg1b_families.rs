//! EG1b: three families from the sealed run of 2026-11-14 that were engine gaps or a spec gap (the last approved by the reviewer 2026-11-14):
//! (1) a key word with a prefix such as `api_token` (`\btoken\b` has no word boundary after `_`); (2) a bare `Bearer <token>` outside an
//! `Authorization:` header; (3) a JWT cut by a hyphen after every few characters. Synthetic values only; the expected results are written by hand.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use base64::Engine;
use common::*;
use entropa_egress::decide::{decide, Action};
use entropa_egress::policy::Tier;

fn act(body: &str) -> Action {
    decide(&text_req(body), &policy(), Tier::T1, &conv(), &Mem::new()).action()
}
fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}
const VALUE: &str = "Ab3dE6gH9jK2mN5p";

#[test]
fn f1_prefixed_key_words_in_an_assignment_are_credentials() {
    for k in [
        "api_token",
        "access_token",
        "my-secret",
        "DB_PASSWORD",
        "client_secret",
        "password",
    ] {
        let a = format!("{k} = \"{VALUE}\"");
        assert_eq!(act(&a), Action::Block, "{a}");
    }
}

#[test]
fn f1b_the_encoded_assignment_with_a_prefixed_key_word_is_seen() {
    let a = format!("api_token = \"{VALUE}\"");
    assert_eq!(act(&b64(&a)), Action::Block, "base64");
    assert_eq!(act(&b64(&b64(&a))), Action::Block, "double base64");
    assert_eq!(act(&hex::encode(&a)), Action::Block, "hex");
    let url: String = a.bytes().map(|c| format!("%{c:02X}")).collect();
    assert_eq!(act(&url), Action::Block, "url encoding");
}

#[test]
fn f1c_near_misses_stay_allowed() {
    for t in [
        "the token budget is large",
        "tokenizer = \"Ab3dE6gH9jK2mN5p\"",
        "api_token = ${API_TOKEN}",
        "token = \"short\"",
    ] {
        assert_eq!(act(t), Action::Allow, "{t}");
    }
}

#[test]
fn f2_a_bare_bearer_with_a_long_mixed_token_is_a_credential() {
    for t in [
        "send Bearer 8f14e45fceea167a5a36dedd4bea2543 now",
        "use bearer abcDEF0123456789xyzABC please",
    ] {
        assert_eq!(act(t), Action::Block, "{t}");
    }
}

#[test]
fn f2b_prose_and_tokens_without_a_letter_and_a_digit_stay_allowed() {
    for t in [
        "the bearer of the message was late",
        "Bearer abcdefghijklmnopqrstuvwx",
        "Bearer 12345678901234567890",
        "Bearer abc123",
        "bearer bonds are bearer instruments issued in 2024",
    ] {
        assert_eq!(act(t), Action::Allow, "{t}");
    }
}

fn jwt() -> String {
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijklmnop".to_string()
}
fn hyphenate(s: &str, g: usize) -> String {
    s.as_bytes()
        .chunks(g)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

#[test]
fn f3_a_jwt_with_a_hyphen_after_every_few_characters_is_recognised() {
    for g in 3..=8 {
        let t = format!("note {} end", hyphenate(&jwt(), g));
        assert_eq!(act(&t), Action::Block, "group size {g}: {t}");
    }
}

#[test]
fn f3b_hyphenated_text_that_is_not_a_jwt_stays_allowed() {
    for t in [
        "ref abcd-efgh-ijkl-mnop-qrst-uvwx-yz12-3456 end".to_string(),
        // eyJ at the start but the header does not decode to JSON with alg
        format!(
            "note {} end",
            hyphenate(
                "eyJhbGciOiJIUzI1NiJ9bad.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijklmnop"
                    .replace("JIUzI1NiJ9", "XXXXXXXXXX")
                    .as_str(),
                4
            )
        ),
    ] {
        assert_eq!(act(&t), Action::Allow, "{t}");
    }
}

// Test change (EG1d, a stage record (not published) part B): the case "irregular hyphens: not a regular grouping of a jwt" was a documented LIMIT of eg1b, written as an expectation (Allow). EG1d
// is ordered to recognise irregular hyphen placement (all hyphens of a line are removed as a candidate), so that one case now expects Block; the other two cases of f3b are unchanged.
#[test]
fn f3c_a_jwt_with_irregular_hyphens_is_now_seen() {
    let t = format!("note {}-x end", hyphenate(&jwt(), 4).replacen('-', "", 1));
    assert_eq!(act(&t), Action::Block, "{t}");
}

#[test]
fn f4_every_format_with_a_hyphen_after_every_four_characters_is_still_a_secret() {
    // the sealed family `case_sep`: the secret text cut into groups of four joined by hyphens, inside a sentence (synthetic values)
    let secrets = [
        ("aws", "AKIAQWERTY0189ABCDEF"),
        ("aws base32", "AKIAIOSFODNN7EXAMPLE"),
        ("github", "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"),
        ("slack", "xoxb-0000000000-0000000000-canaryCANARYcanary00"),
        ("stripe", "sk_live_canarycanarycanary00"),
        ("openai", "sk-canarycanarycanarycanarycanarycanary"),
        ("google", "AIzaSyCanaryCanaryCanaryCanaryCanary012345"),
        ("npm", "npm_canarycanarycanarycanarycanarycanary"),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijklmnop",
        ),
    ];
    let mut missed = Vec::new();
    for (name, s) in secrets {
        let t = format!("Please check {} before sending.", hyphenate(s, 4));
        if act(&t) != Action::Block {
            missed.push(format!("{name}: {t}"));
        }
    }
    assert!(missed.is_empty(), "not blocked: {missed:#?}");
}
