//! EG1f mutation survivors, part 1: exact-value unit cases for the context detector (a stage record (not published), docs/evidence/eg1f/mutation-run3-missed.txt).
//! Written AFTER the code, to kill the survivors of mutation run 3 (listed per case). Every expected value below is derived by hand from the syntax rule it names, not copied from the
//! detector's output; each case asserts the exact text of every finding, so a shifted or truncated value fails. Synthetic words only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::context::{analyze, Analysis, Hit};

const V: &str = "Xk39fQ2zLp";

fn texts(t: &str, hits: &[Hit]) -> Vec<String> {
    hits.iter().map(|h| t[h.start..h.end].to_string()).collect()
}
fn check(t: &str, secrets: &[&str], refs: &[&str]) {
    let a: Analysis = analyze(t);
    let want = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    assert_eq!(texts(t, &a.secrets), want(secrets), "secrets for {t:?}");
    assert_eq!(texts(t, &a.references), want(refs), "references for {t:?}");
}
fn sec(t: &str, v: &str) {
    check(t, &[v], &[]);
}
fn none(t: &str) {
    check(t, &[], &[]);
}
fn rf(t: &str, v: &str) {
    check(t, &[], &[v]);
}

#[test]
fn u1_separators_between_the_letters_of_a_key_word_are_limited_to_three() {
    sec(&format!("pass---word={V}"), V);
    none(&format!("pass----word={V}"));
    none(&format!("s-----e-----c-----r-----e-----t={V}"));
}

#[test]
fn u2_the_tail_of_the_identifier_decides_whether_it_is_a_key() {
    none(&format!("password_policy={V}"));
    none(&format!("secretary={V}"));
    sec(&format!("secrets={V}"), V);
    none(&format!("secret_s={V}"));
    sec(&format!("api_key_value={V}"), V);
    sec(&format!("apikeys={V}"), V);
    sec(&format!("token2={V}"), V);
    sec(&format!("token_2={V}"), V);
    sec(&format!("token_2_new={V}"), V);
    sec(&format!("token12={V}"), V);
    none(&format!("token 2: {V}"));
    none("token12");
    sec(&format!("secret---key={V}"), V);
    none(&format!("secret----key={V}"));
    sec(&format!("secret:key={V}"), V);
    // a colon not followed by a letter is the assignment, not part of the name: the value is the rest of the line
    sec(&format!("token:_key={V}"), &format!("_key={V}"));
}

#[test]
fn u3_a_secret_word_glued_inside_a_longer_word_is_not_a_key_but_camel_case_is() {
    none(&format!("xpassword={V}"));
    sec(&format!("myPassword={V}"), V);
}

#[test]
fn u4_the_line_start_is_the_previous_newline() {
    sec(
        "foo\npassword=island ember 42! harbor",
        "island ember 42! harbor",
    );
    sec(
        "a\nb\nc\npassword: island ember 42! harbor",
        "island ember 42! harbor",
    );
}

#[test]
fn u5_placeholders_need_less_than_four_characters_left() {
    sec("password = \"your-abcd-here\"", "your-abcd-here");
    rf("password = \"your-abc-here\"", "your-abc-here");
}

#[test]
fn u6_references_and_templates_are_found_by_their_own_prefix_and_keep_their_exact_extent() {
    rf("password = <abcdefgh", "<abcdefgh");
    rf("password = [abcdefgh", "[abcdefgh");
    rf("password = %{abcdefgh", "%{abcdefgh");
    rf("password = [env:PWD_X]tail", "[env:PWD_X]");
    rf("password = {{ vault.pwd }}", "{{ vault.pwd }");
    rf("password = ${VAULT_PWD}", "${VAULT_PWD}");
    rf("password = <vault:secret/x>", "<vault:secret/x>");
    rf("password = <vault:x> tail", "<vault:x>");
    // a call on a variable: `$name(` is a variable expression, not a literal
    rf("password = $getpwd(x)", "$getpwd(x");
    rf("password = %(vault_pwd)s", "%(vault_pwd)");
    rf("password = $(getpwd1)", "$(getpwd1");
    sec("password = %abcdefg tail more", "%abcdefg");
    // quoted values that start like a template are templates
    rf("password = \"<%abcdefgh\"", "<%abcdefgh");
    rf("password = \"<abcdefgh>\"", "<abcdefgh>");
    rf("password = \"[abcdefgh]\"", "[abcdefgh]");
    sec(&format!("password = \"{V}>\""), &format!("{V}>"));
    sec(&format!("password = \"{V}]\""), &format!("{V}]"));
    sec(&format!("password = \"<{V}\""), &format!("<{V}"));
}

#[test]
fn u7_a_dollar_followed_by_symbols_is_not_a_variable() {
    sec("password = $w~A%k9Zx", "$w~A%k9Zx");
    sec("password = $abc-defg1", "$abc-defg1");
    rf("password = $this->secretvalue", "$this->secretvalue");
    sec("password = $ab->$xyz99", "$ab->$xyz99");
    sec("password = $ab[1]~xyz", "$ab[1]~xyz");
    rf("password = $args[0]", "$args[0]");
    // a long mixed token that happens to start with a dollar sign is a token
    sec("token = $Xk39fQ2zLpab", "$Xk39fQ2zLpab");
}

#[test]
fn u8_in_code_style_only_an_identifier_that_does_not_look_like_a_secret_is_a_variable() {
    sec("password = ab-cd-ef", "ab-cd-ef");
    sec("password = 12345678abc", "12345678abc");
    rf("password = _abcdefgh", "_abcdefgh");
    rf("password = hunter_value", "hunter_value");
    sec(&format!("password = {V}"), V);
    rf(&format!("password = {}", "q".repeat(39)), &"q".repeat(39));
    sec(&format!("password = {}", "q".repeat(40)), &"q".repeat(40));
}

#[test]
fn u9_a_quoted_key_opens_a_quote_that_the_value_runs_to() {
    sec("'password: (\"Xk39fQ2zLp\")'", "(\"Xk39fQ2zLp\")");
    sec("say \"password: reviewed\" now", "reviewed");
    // the extent of an unquoted value runs to the closing quote of the key's own quote
}

#[test]
fn u10_prose_keys_need_a_value_that_looks_like_one() {
    sec("api key: ab12cd34", "ab12cd34");
    rf("api key: reviewed", "reviewed");
    sec("api key: ab-cd-efg", "ab-cd-efg");
    sec("api key: abcdefghijklm", "abcdefghijklm");
    rf("api key: abcdefghijk", "abcdefghijk");
    // a key in the middle of a line followed by a colon is prose unless something marks it as a field
    rf("set password: reviewed", "reviewed");
    sec("password: reviewed", "reviewed");
    sec("say password\": reviewed", "reviewed");
    sec(
        "say password\": island ember 42! harbor",
        "island ember 42! harbor",
    );
    rf("=password: island ember 42! harbor", "island");
}

#[test]
fn u11_path_like_keys_count_as_one_key_token() {
    sec(
        "vault/kv/token: island ember 42! harbor",
        "island ember 42! harbor",
    );
}

#[test]
fn u12_the_assignment_operators() {
    none("password == Xk39fQ2zLp");
    none("password ==Xk39fQ2zLp");
    none("password==Xk39fQ2zLp");
    none("password://Xk39fQ2zLp");
    none("password::abcdefgh");
    rf("password= abcdefgh", "abcdefgh");
    rf("password =abcdefgh", "abcdefgh");
    sec("password=abcdefgh", "abcdefgh");
    rf("token -> abcdefgh", "abcdefgh");
    rf("token ->abcdefgh", "abcdefgh");
    none("password -= Xk39fQ2zLp");
}

#[test]
fn u13_minimum_value_length_is_six_in_every_path() {
    sec("password=Xk39fQ", "Xk39fQ");
    none("password=Xk39f");
    sec("<password>Xk39fQ</password>", "Xk39fQ");
    none("<password>Xk39f</password>");
    sec("mytool --password Xk39fQ", "Xk39fQ");
    none("mytool --password Xk39f");
    sec("<password>Xk39fQ</password>", "Xk39fQ");
}

#[test]
fn u14_keyword_values_without_an_operator() {
    none("Bearer abcdefgh");
    sec("Bearer abcdefghijklmnop", "abcdefghijklmnop");
    none("Bearer abcdefghijklmno");
    sec("Bearer ab-cdefgh", "ab-cdefgh");
    none("Bearer ab_cdefgh");
    sec("CREATE USER x IDENTIFIED BY abcdefgh", "abcdefgh");
    sec("mytool --password \"abcdefgh\"", "abcdefgh");
    sec(&format!("Authorization: Bearer {V}"), V);
    // a bare scheme word with no value is a fragment (a reference), and a text that ends right after it must not panic
    rf("Authorization: Bearer", "Bearer");
    none("Authorization: Token"); // five characters: under the minimum value length
}

#[test]
fn u15_terraform_default_at_the_end_of_the_text_does_not_panic() {
    none("password {default   ");
    none("password {default");
    sec("variable \"password\" { default = \"Xk39fQ2zLp\" }", V);
}

#[test]
fn u16_yaml_tags_are_references() {
    rf("password: !secret client_pw", "!secret client_pw");
}

#[test]
fn u17_values_are_cut_at_the_documented_limit_of_4096_bytes() {
    let long = "a".repeat(5000);
    let a = analyze(&format!("password = \"{}\"", "aXk3".repeat(1250)));
    assert_eq!(a.secrets.len(), 1);
    assert_eq!(a.secrets[0].end - a.secrets[0].start, 4096, "quoted");
    let t = format!("password = {}", "Qk39".repeat(1250));
    let a = analyze(&t);
    assert_eq!(a.secrets.len(), 1);
    assert_eq!(a.secrets[0].end - a.secrets[0].start, 4096, "plain");
    let a = analyze(&format!("password = <{long}"));
    assert_eq!(a.references.len(), 1);
    assert_eq!(
        a.references[0].end - a.references[0].start,
        4097,
        "bracketed"
    );
    let a = analyze(&format!("x \"password: {long}"));
    assert_eq!(a.secrets.len(), 1);
    assert_eq!(
        a.secrets[0].end - a.secrets[0].start,
        4096,
        "inside a key quote"
    );
    let a = analyze(&format!("password: {long}"));
    assert_eq!(a.secrets.len(), 1);
    assert_eq!(
        a.secrets[0].end - a.secrets[0].start,
        4096,
        "to the end of the line"
    );
}

#[test]
fn u18_value_extents() {
    // an escaped quote does not end a quoted value
    sec("password = \"ab\\\"cdefgh\"", "ab\\\"cdefgh");
    // an unquoted value ends at a comma, but an index is read as a unit
    rf("password = abcdefgh, x]", "abcdefgh");
    none(&format!("password = ab[ {}]", "x".repeat(300)));
    // the value of a properties or YAML line runs to the end of the line and loses trailing blanks
    sec("password: abcdefgh   ", "abcdefgh");
    sec(
        "say password\": island ember 42! harbor",
        "island ember 42! harbor",
    );
    sec(
        "password=island ember 42! harbor",
        "island ember 42! harbor",
    );
    sec("<password>Xk39fQ2zLp</password>", V);
    rf("password = <vault:x>", "<vault:x>");
}

// ---- added AFTER the EG1f freeze (the advisor review found two survivor arguments that were wrong); the frozen source is unchanged ----

#[test]
fn u19_a_value_can_be_one_character_after_trimming_and_a_mask_is_not_a_placeholder() {
    // a quote-open value keeps its trailing blanks (six bytes), but the reference test trims it to a single `$`: it must not be read as a variable expression and must not panic
    rf("say \"password: $     \" now", "$     ");
    rf("say \"password: !a    \" now", "!a    ");
    // separated x's are a mask but NOT a placeholder (no `xxx` run to remove, four letters left): only the mask rule makes them a reference
    rf("password = x-x-x-x", "x-x-x-x");
    rf("password = \"x-x-x-x\"", "x-x-x-x");
    rf("password: x.x.x.x", "x.x.x.x");
    rf("password = ********", "********");
}
