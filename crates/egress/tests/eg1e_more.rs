//! EG1e tests written AFTER the code, for the cases the DEV runs found (disclosed in a stage record (not published)): YAML tags versus values that start with `!`, values that start with `$`, `curl -u`,
//! nested parentheses, the digit tail of a placeholder, and exact outputs of the separator removal. Each is bite-checked by hand mutation (docs/evidence/eg1e/bite.txt).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action};
use entropa_egress::policy::Tier;
use entropa_egress::views::{remove_separators, remove_separators_keep_spaces};

fn act(body: &str) -> Action {
    decide(&text_req(body), &policy(), Tier::T1, &conv(), &Mem::new()).action()
}

#[test]
fn n1_a_yaml_tag_is_a_reference_but_a_value_that_merely_starts_with_a_bang_is_not() {
    assert_eq!(act("password: !vault_reference"), Action::Allow);
    assert_eq!(act("password: !Ux/G//X3x%?ZmSee"), Action::Block);
    assert_eq!(act("api_key=!xCCHugbC=^lKH6l!L=*r%"), Action::Block);
}

#[test]
fn n2_a_dollar_variable_is_a_reference_but_a_value_that_merely_starts_with_a_dollar_is_not() {
    assert_eq!(act("token=$TOKEN_VALUE_X"), Action::Allow);
    assert_eq!(act("client_secret = ${CLIENT_SECRET}"), Action::Allow);
    assert_eq!(act("client_secret=$hq+Qz/R6Fs+Y#2j=Bx"), Action::Block);
    assert_eq!(
        act("curl -H \"Authorization: Bearer $999A&A!9A9!AAaA9AaAa9a\" https://x.example/api"),
        Action::Block
    );
    assert_eq!(
        act("curl -H \"Authorization: Bearer $API_TOKEN\" https://x.example/api"),
        Action::Allow
    );
}

#[test]
fn n3_curl_basic_auth_with_a_literal_password_is_blocked() {
    assert_eq!(
        act("curl -u admin:Ab3dE6gH9jK2mN5p https://x.example/api"),
        Action::Block
    );
    assert_eq!(
        act("curl --user admin:W/1IInk8Ko/hQUgB https://x.example/api"),
        Action::Block
    );
    assert_eq!(
        act("curl -u admin:$PASSWORD https://x.example/api"),
        Action::Allow
    );
    assert_eq!(act("curl -u admin https://x.example/api"), Action::Allow);
}

#[test]
fn n4_nested_parentheses_are_stripped_and_a_short_inside_is_not_judged() {
    assert_eq!(act("token = ((a.b.c))"), Action::Allow);
    assert_eq!(act("token = ((value))"), Action::Allow);
    assert_eq!(act("token = ((\"Ab3dE6gH9jK2mN5p\"))"), Action::Block);
    assert_eq!(act("secret = (((settings.API_KEY_NAME)))"), Action::Allow);
}

#[test]
fn n5_a_placeholder_word_does_not_hide_a_digit_tail() {
    assert_eq!(act("apiKey = \"changemeAu07e164\""), Action::Block);
    assert_eq!(act("password = \"changeme1\""), Action::Allow);
    assert_eq!(act("password = \"your_password_here\""), Action::Allow);
}

#[test]
fn n6_the_separator_removal_has_exact_outputs() {
    assert_eq!(
        remove_separators_keep_spaces("Au-tho-riz-ation: Be-ar-er X").as_deref(),
        Some("Authorization: Bearer X")
    );
    assert_eq!(
        remove_separators_keep_spaces("Bearer-_ BFt--a4").as_deref(),
        Some("Bearer BFta4"),
        "a real space next to a separator stays"
    );
    assert_eq!(
        remove_separators("Autho- rizatio- n: Be-ar-er X").as_deref(),
        Some("Authorization: Bearer X"),
        "a space that touches a separator goes"
    );
    assert_eq!(
        remove_separators("api_-key=Xk9").as_deref(),
        Some("apikey=Xk9"),
        "two touching separators are enough"
    );
    assert_eq!(
        remove_separators("a-b c.d_e").as_deref(),
        Some("ab cde"),
        "three separators"
    );
    assert_eq!(
        remove_separators("a-b c"),
        None,
        "one separator is not enough"
    );
    assert_eq!(
        remove_separators("well-known snake_case"),
        None,
        "two apart is not enough"
    );
}

// ---- mutation triage (first run on the new functions: 56 mutants, 11 missed) ----
#[test]
fn q1_every_bearer_template_is_a_placeholder_and_a_lookalike_is_not() {
    for ok in [
        "{{token_value_x}}",
        "%(token_value)s",
        "<your-token-here>",
        "${API_TOKEN_X}",
        "$(cat token.txt)",
        "$_TOKEN_VALUE",
        "$API_TOKEN",
    ] {
        assert_eq!(
            act(&format!("Authorization: Bearer {ok}")),
            Action::Allow,
            "{ok}"
        );
    }
    for bad in [
        "{token_value_x1}",
        "%token_value_x1",
        "$1token_value_x",
        "$token-value-x1",
        "$$token_value_x1",
        "(Ab3dE6gH9jK2)",
    ] {
        assert_eq!(
            act(&format!("Authorization: Bearer {bad}")),
            Action::Block,
            "{bad}"
        );
    }
}

#[test]
fn q2_the_eight_character_minimum_and_the_env_line_shapes() {
    assert_eq!(
        act("password = Ab3dE6gH"),
        Action::Block,
        "exactly 8 characters is judged"
    );
    assert_eq!(
        act("password = Ab3dE6g"),
        Action::Allow,
        "7 characters is not"
    );
    assert_eq!(
        act("connect(password=db_password_value)"),
        Action::Allow,
        "a keyword argument is code, not an env line"
    );
    assert_eq!(
        act("password=db_password_value"),
        Action::Block,
        "an env line at the start of a line is a literal"
    );
    assert_eq!(
        act("  export password=db_password_value"),
        Action::Block,
        "export"
    );
    assert_eq!(
        act("x = 1; password=db_password_value"),
        Action::Allow,
        "after code on the same line it is code"
    );
}

#[test]
fn q3_the_placeholder_remainder_is_judged_at_four_characters() {
    assert_eq!(
        act("password = \"changemeabcd\""),
        Action::Block,
        "four left"
    );
    assert_eq!(
        act("password = \"changemeabc\""),
        Action::Allow,
        "three left"
    );
}

#[test]
fn q4_the_two_removal_variants_differ_exactly_by_the_spaces() {
    assert_eq!(
        remove_separators_keep_spaces("ab -c.d_e").as_deref(),
        Some("ab cde")
    );
    assert_eq!(remove_separators("ab -c.d_e").as_deref(), Some("abcde"));
    assert_eq!(remove_separators("a- b.c_d").as_deref(), Some("abcd"));
    assert_eq!(
        remove_separators_keep_spaces("a- b.c_d").as_deref(),
        Some("a bcd")
    );
}

#[test]
fn q5_in_a_key_value_line_only_a_template_a_vault_reference_a_tag_or_a_command_is_a_reference() {
    for ok in [
        "password: {{vault_token_x}}",
        "password: ref+vault://secret/app#token",
        "password: !vault_reference",
        "password: `vault read -field=value secret/app`",
        "SECRET=`vault read -field=value secret/app`",
        "password: `cat_secret_file_x`",
    ] {
        assert_eq!(act(ok), Action::Allow, "{ok}");
    }
    for bad in [
        "password: {vault_token_x1}",
        "password: ref-vault-secret-app-1",
        "password: vault_read_secret_app",
    ] {
        assert_eq!(act(bad), Action::Block, "{bad}");
    }
}
