//! EG1c red tests (a stage record (not published)): a keyword-anchored credential whose KEYWORD is disguised together with its value: the whole phrase cut by a hyphen every g characters (g = 3 to 8),
//! reversed, or rot13. Synthetic values only; the expected results are written by hand (Block for every disguised credential, Allow for the near misses that Allow today).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action};
use entropa_egress::policy::Tier;

fn act(body: &str) -> Action {
    decide(&text_req(body), &policy(), Tier::T1, &conv(), &Mem::new()).action()
}
const T: &str = "Cn5WJHxOY6UF2EkNqdM5QdDG2tZ8";
fn phrases() -> Vec<(&'static str, String)> {
    vec![
        ("authz_bearer", format!("Authorization: Bearer {T}")),
        ("bearer", format!("Bearer {T}")),
        ("password", format!("password = \"{T}\"")),
        ("token", format!("token = \"{T}\"")),
        ("api_key", format!("api_key = \"{T}\"")),
        ("secret", format!("secret: {T}")),
    ]
}
fn hyphen(s: &str, g: usize) -> String {
    s.chars()
        .collect::<Vec<_>>()
        .chunks(g)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            o => o,
        })
        .collect()
}
fn among_prose(line: &str) -> String {
    format!("Notes from the call:\n{line}\nLet me know if that helps.")
}

#[test]
fn h1_the_whole_phrase_cut_by_a_hyphen_every_g_characters_is_blocked() {
    for (name, p) in phrases() {
        for g in 3..=8 {
            let d = hyphen(&p, g);
            assert_eq!(act(&d), Action::Block, "{name} g={g} alone: {d}");
            assert_eq!(
                act(&among_prose(&d)),
                Action::Block,
                "{name} g={g} among prose"
            );
        }
    }
}

#[test]
fn h2_the_whole_phrase_reversed_is_blocked() {
    for (name, p) in phrases() {
        let d: String = p.chars().rev().collect();
        assert_eq!(act(&d), Action::Block, "{name} alone: {d}");
        assert_eq!(act(&among_prose(&d)), Action::Block, "{name} among prose");
    }
}

#[test]
fn h3_the_whole_phrase_rot13_is_blocked() {
    for (name, p) in phrases() {
        let d = rot13(&p);
        assert_eq!(act(&d), Action::Block, "{name} alone: {d}");
        assert_eq!(act(&among_prose(&d)), Action::Block, "{name} among prose");
    }
}

#[test]
fn h4_near_misses_that_allow_today_stay_allowed() {
    let prose =
        "The bearer of the news was the courier. Reset your password from the settings page.";
    let part = "Part numbers: AB12-CD34-EF56, 90AB-12CD-34EF, 7A7A-B8B8-C9C9";
    for t in [
        prose.to_string(),
        prose.chars().rev().collect::<String>(),
        rot13(prose),
        part.to_string(),
        hyphen("Ledger audit budget invoice contract", 4),
        among_prose("the token budget is large"),
        rot13("the token budget is large"),
        "token = \"short\"".chars().rev().collect::<String>(),
    ] {
        assert_eq!(act(&t), Action::Allow, "{t}");
    }
}
