//! EG1e red tests (a stage record (not published), the reviewer's decisions D1 to D4 of 2026-11-16). Hand-written examples; synthetic values only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action};
use entropa_egress::policy::Tier;

fn act(body: &str) -> Action {
    decide(&text_req(body), &policy(), Tier::T1, &conv(), &Mem::new()).action()
}
fn block(t: &str) {
    assert_eq!(act(t), Action::Block, "{t}");
    assert_eq!(
        act(&format!("Notes:\n{t}\nThanks.")),
        Action::Block,
        "among prose: {t}"
    );
}
fn allow(t: &str) {
    assert_eq!(act(t), Action::Allow, "{t}");
    assert_eq!(
        act(&format!("Notes:\n{t}\nThanks.")),
        Action::Allow,
        "among prose: {t}"
    );
}

#[test]
fn c1_symbol_rich_bearer_values_are_blocked_in_every_curl_shape() {
    for v in [
        "AaA#aA9aaA!!9aA^AA",
        "a*A#9-AA9A9-9aaa",
        "*99Aa9999a9#a9a9aa",
        "$999A&A!9A9!AAaA9AaAa9a",
        "Xk9?fQ2zLp+7W=mN~4",
        "9aaaaaaaaaaaaaaaaaaaaaaaa.",
        "A9@%b8",
    ] {
        for line in [
            format!("curl -H \"Authorization: Bearer {v}\" https://x.example:8443/v1/items"),
            format!("curl -H 'Authorization: Bearer {v}' https://x.example/api"),
            format!("curl https://x.example/api -H \"Authorization: Bearer {v}\""),
            format!("curl --header \"Authorization: Bearer {v}\" https://x.example/api"),
            format!("Found this in the repo:\n```\ncurl -H \"Authorization: Bearer {v}\" https://x.example/api\n```\nThanks."),
            format!("Authorization: Bearer {v}"),
        ] {
            if v.len() >= 12 {
                assert_eq!(act(&line), Action::Block, "{line}");
            }
        }
    }
    // placeholders and variables after Bearer stay allowed
    for ok in [
        "Authorization: Bearer ${API_TOKEN}",
        "curl -H \"Authorization: Bearer $TOKEN\" https://x.example/api",
        "Authorization: Bearer <your-token-here>",
        "curl -H \"Authorization: Bearer $(cat token.txt)\" x",
    ] {
        assert_eq!(act(ok), Action::Allow, "{ok}");
    }
}

#[test]
fn c2_a_quoted_value_is_a_literal_in_every_language() {
    for l in [
        "password = \"correct_horse_battery_staple\"",
        "password = 'river.stone.lantern'",
        "const api_key = \"river-stone-lantern-harbor\";",
        "token := \"copperWillowMeadow\"",
        "String secret = \"anchor_beacon_canyon\";",
        "let client_secret = \"delta_glacier_harvest\";",
        "$config{password} = \"river_stone_lantern\"",
    ] {
        block(l);
    }
}

#[test]
fn c3_an_unquoted_value_in_a_key_value_line_is_a_literal_but_a_variable_in_code_position_is_not() {
    for l in [
        "password: correct_horse_battery",
        "api_key: river.stone.lantern",
        "{\"password\": \"correct_horse_battery\"}",
        "export API_KEY=correct_horse_battery",
        "SECRET=river_stone_lantern_harbor",
    ] {
        block(l);
    }
    for l in [
        "password = db_password",
        "const token = authToken;",
        "api_key = settings.API_KEY",
        "this.secret = self.secret_value",
        "token := self.secret",
        "password = tokenValue  # from the vault",
    ] {
        allow(l);
    }
}

#[test]
fn c4_the_ini_shape_is_a_stated_limit_not_a_claim() {
    // `password = correct_horse_battery` in an INI file is identical to `password = db_password` in Python: judged a reference, so it LEAKS. Pinned so the limit cannot change silently.
    assert_eq!(
        act("[auth]\npassword = correct_horse_battery"),
        Action::Allow
    );
}

#[test]
fn c5_a_placeholder_is_allowed_only_when_nothing_of_four_characters_is_left() {
    for ok in [
        "changeme",
        "changeme-placeholder",
        "your_password_here",
        "xxxxxxxx",
        "dummy-example",
        "sample_placeholder",
        "todo",
        "redacted",
        "changeme-here",
    ] {
        assert_eq!(act(&format!("password = \"{ok}\"")), Action::Allow, "{ok}");
    }
    for bad in [
        "changeme-Xk39fQ2zLp",
        "example-r4nd0mTail",
        "dummy_Qk8vL2xW",
        "your_token_Ab3dE6gH9j",
        "sampleZk93LpWq",
    ] {
        assert_eq!(
            act(&format!("password = \"{bad}\"")),
            Action::Block,
            "{bad}"
        );
    }
}

#[test]
fn c6_one_level_of_parentheses_is_stripped_and_the_inside_is_judged() {
    for ok in [
        "token = (x or default)",
        "api_key = (f())",
        "secret = (cfg.token)",
        "password = ((os.getenv('TOKEN') or ''))",
        "token = (settings.API_KEY) if on else None",
    ] {
        allow(ok);
    }
    for bad in [
        "token = (\"Ab3dE6gH9jK2mN5pQ7r\")",
        "api_key = (\"river_stone_lantern\" or \"\")",
        "secret = ('Xk9fQ2zLp7WmN4')",
    ] {
        block(bad);
    }
}

#[test]
fn c7_a_phrase_chopped_by_mixed_separators_keyword_and_value_is_seen() {
    for l in [
        "Au-tho-riz-ation: Be-ar-er Xk9_fQ2-zLp7Wm-N4rT6vB",
        "pa-ssw-ord=Xk9fQ2-zLp7Wm-N4#rT6v",
        "ap-i_-key=Xk9fQ2zLp7WmN4rT6vB1",
        "cl-ient_s-ecret=Xk9fQ2-zLp7_WmN4rT6vB1",
        "Please check: tok-.en=Xk9fQ2zLp7WmN4rT6vB1x. Thanks.",
        "Au-_tho-riz-.ation: Be-ar-_er Xk9fQ2zLp7WmN4rT6vB1x",
    ] {
        assert_eq!(act(l), Action::Block, "{l}");
    }
    for ok in [
        "The well-known long-term plan is end-to-end.",
        "See pages 12-48 and figures 3-17 in the file_name.v2.pdf",
        "Use snake_case_names and dotted.names.here in the docs.",
    ] {
        assert_eq!(act(ok), Action::Allow, "{ok}");
    }
}

#[test]
fn c8_a_chopped_phrase_in_the_middle_of_a_prose_line_is_seen() {
    for l in [
        "lantern quartz glacier cedar willow Au-tho-riz-ation: Be-ar-er Xk9fQ2zLp7WmN4rT6vB1x delta stone ember",
        "one two three four five six pa-ss-wor-d=Xk9fQ2zLp7WmN4rT6vB1x seven eight",
        "river stone lantern harbor copper tok--en=Xk9fQ2--zLp7Wm--N4rT6vB1x meadow falcon ember",
        "alpha beta gamma delta api_-key=Xk9fQ2zLp7WmN4rT6vB1x one two",
    ] {
        assert_eq!(act(l), Action::Block, "{l}");
    }
}
