//! EG1b mutation triage, batch J: `url_findings` (where a URL ends, credentials in the authority, suspicious DNS labels), the conversation tail clipped inside a
//! multibyte character, and a match split across fields that cannot be redacted. Rules: a URL in text ends at whitespace or one of " ' < > ) ]; an `@` in the
//! authority is a credential (`credential_structure`); a host label over 63 characters, or of 24 or more with an entropy of at least 3.5 bits per character, is a
//! `dns_label_suspect`; a tail longer than its limit is clipped to the limit, moved forward to a character boundary; a redact-mode match that spans two fields cannot be
//! rewritten, so the request is blocked. Equivalent (a stage record (not published)): the `is_char_boundary` loop of the guard prefix in `scan_text` (the stripped key and card
//! patterns match ASCII only, so the prefix end is always a boundary), and the residual re-check (it needs a redaction that creates a new match, which the stable
//! placeholders prevent; the fault-injected path is tested).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action, Conversation, Reason};
use entropa_egress::policy::Tier;

fn run(t: &str) -> (Action, Reason) {
    let d = decide(&text_req(t), &policy(), Tier::T1, &conv(), &Mem::new());
    (d.action(), d.reason())
}

#[test]
fn j1_a_url_ends_at_whitespace_or_a_closing_character_so_an_at_sign_after_it_is_not_a_credential() {
    for end in [" ", "\"", "'", "<", ">", ")", "]", "\n", "\t"] {
        let t = format!("link https://ok.example.invalid{end}and then a@b is a note");
        assert_eq!(run(&t), (Action::Allow, Reason::Clean), "{end:?}");
    }
    // the same at sign inside the authority is a credential
    assert_eq!(
        run("link https://user@ok.example.invalid/x"),
        (Action::Block, Reason::CredentialStructure)
    );
    assert_eq!(
        run("link https://user:pw@ok.example.invalid:8443/x"),
        (Action::Block, Reason::CredentialStructure)
    );
    // an at sign in the PATH is not in the authority
    assert_eq!(
        run("link https://ok.example.invalid/a@b"),
        (Action::Allow, Reason::Clean)
    );
    // other schemes are not inspected
    assert_ne!(
        run("link ftp://user@ok.example.invalid/x").1,
        Reason::CredentialStructure,
        "only http and https URLs are inspected for credentials"
    );
}

#[test]
fn j2_dns_label_rules_have_exact_boundaries() {
    let l63 = "a".repeat(63);
    let l64 = "a".repeat(64);
    assert_eq!(
        run(&format!("see https://{l63}.example.invalid/x")),
        (Action::Allow, Reason::Clean),
        "63 characters, low entropy"
    );
    assert_eq!(
        run(&format!("see https://{l64}.example.invalid/x")),
        (Action::Block, Reason::DnsLabelSuspect),
        "64 characters"
    );
    // 24 distinct characters: 4.58 bits each, so a label of 24 is suspect and one of 23 is not
    assert_eq!(
        run("see https://abcdefghijklmnopqrstuvwx.example.invalid/x"),
        (Action::Block, Reason::DnsLabelSuspect),
        "24 high-entropy characters"
    );
    assert_eq!(
        run("see https://abcdefghijklmnopqrstuvw.example.invalid/x").0,
        Action::Allow,
        "23 high-entropy characters are not a suspect label (an entropy record is fine)"
    );
    // long but low entropy (24 or more) is fine; short but high entropy is fine
    assert_eq!(
        run(&format!(
            "see https://{}.example.invalid/x",
            "ab".repeat(15)
        )),
        (Action::Allow, Reason::Clean)
    );
    assert_eq!(
        run("see https://abcdefghijklmn.example.invalid/x").0,
        Action::Allow,
        "14 distinct characters is 3.8 bits but only 14 long"
    );
}

#[test]
fn j3_a_long_tail_cut_inside_a_multibyte_character_is_moved_to_a_boundary() {
    // 2,500 two-byte characters and an a: 5,001 bytes; the limit is 4,096, so the cut falls at byte 905, in the middle of a character
    let tail = format!("{}a", "\u{e9}".repeat(2500));
    assert_eq!(tail.len(), 5001);
    let c = Conversation {
        key: b"conversation-key-0001".to_vec(),
        tail,
        seen: vec![],
    };
    let d = decide(&text_req("hello"), &policy(), Tier::T1, &c, &Mem::new());
    assert_eq!(
        (d.action(), d.reason()),
        (Action::Allow, Reason::Clean),
        "a clean request with a multibyte tail"
    );
    // a key at the very end of the tail still joins the start of the request
    let tail = format!("{}AKIAIOSFO", "\u{e9}".repeat(2500));
    let c = Conversation {
        key: b"conversation-key-0001".to_vec(),
        tail,
        seen: vec![],
    };
    let d = decide(
        &text_req("DNN7EXAMPLE"),
        &policy(),
        Tier::T1,
        &c,
        &Mem::new(),
    );
    assert_eq!(
        d.action(),
        Action::Block,
        "a key split between the tail and the new message is found: {:?}",
        d.reason()
    );
}

#[test]
fn j4_a_redact_mode_match_split_over_two_fields_cannot_be_rewritten_and_is_blocked() {
    let d = decide(
        &json_req(r#"{"a":"write to jane.doe@exam","b":"ple.invalid now"}"#),
        &policy(),
        Tier::T1,
        &conv(),
        &Mem::new(),
    );
    assert_eq!(d.action(), Action::Block, "{:?}", d.reason());
    // the same email whole in one field is redacted, not blocked
    let d = decide(
        &json_req(r#"{"a":"write to jane.doe@example.invalid now","b":"x"}"#),
        &policy(),
        Tier::T1,
        &conv(),
        &Mem::new(),
    );
    assert_eq!(d.action(), Action::Redact);
}
