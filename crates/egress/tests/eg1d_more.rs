//! EG1d tests added AFTER the code for three small items found with the DEV baseline (disclosed in a stage record (not published)): the `SKU` product code that looked like an `sk` key, a keyword
//! cut by a space, and a hyphen-cut text without any space. Each is checked against a hand mutation of the code (docs/evidence/eg1d/bite.txt).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action};
use entropa_egress::policy::Tier;

fn act(body: &str) -> Action {
    decide(&text_req(body), &policy(), Tier::T1, &conv(), &Mem::new()).action()
}
fn hyphen(s: &str, g: usize) -> String {
    s.chars()
        .collect::<Vec<_>>()
        .chunks(g)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

#[test]
fn m1_a_product_code_starting_with_sku_is_not_an_sk_key_but_a_chunked_sk_key_still_is() {
    for t in [
        "SKU GH849-EF863-CD595-CD336-EF434 ships Monday.",
        "SKU AB123-CD456-EF789-GH012-AB345-CD678 ships Monday.",
        "For the record:\nSKU CD682-CD212-EF232-EF201-GH300 ships Monday.\nThat is all.",
    ] {
        assert_eq!(act(t), Action::Allow, "{t}");
    }
    let key = "sk-Ab3dE6gH9jK2mN5pQ7rS9tU1vW3xY5zA7bC9dE1f";
    assert_eq!(act(key), Action::Block, "plain");
    assert_eq!(act(&hyphen(key, 4)), Action::Block, "hyphen-grouped");
    assert_eq!(
        act(&format!("use {}", hyphen(key, 5))),
        Action::Block,
        "hyphen-grouped mid-line"
    );
}

#[test]
fn m2_a_keyword_cut_by_a_space_or_a_zero_width_character_is_joined() {
    let t = "Ab3dE6gH9jK2mN5pQ7rS9tU1vW";
    for l in [
        format!("pa ssword = \"{t}\""),
        format!("api_ key = \"{t}\""),
        format!("Authorization: Bea rer {t}"),
        format!("sec ret: {t}"),
        format!("pass\u{200b}word = \"{t}\""),
        format!("Notes:\nto ken = \"{t}\"\nThanks."),
    ] {
        assert_eq!(act(&l), Action::Block, "{l:?}");
    }
    for l in [
        "Please keep a pass word list in the vault.",
        "The to ken budget is two million.",
        "A secret garden, a bear er of news.",
    ] {
        assert_eq!(act(l), Action::Allow, "{l}");
    }
}

#[test]
fn m3_a_hyphen_cut_text_without_any_space_is_seen() {
    let t = "https://svc.example.invalid/v1/items?token=ifkkuYrpFOaVD3Dpq6XLuAs1&limit=5";
    for g in 3..=9 {
        assert_eq!(act(&hyphen(t, g)), Action::Block, "g={g}");
    }
    assert_eq!(
        act("https://svc.example.invalid/v1/items?page=2&limit=5"),
        Action::Allow
    );
}
