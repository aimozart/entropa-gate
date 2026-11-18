//! EG1d mutation triage (tests only): exact-output tests of the new helper functions (survivors of the first cargo-mutants run on them). Synthetic values only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::detect::{looks_like_secret, reference_value};
use entropa_egress::views::{join_split_keywords, leaf_expansions, remove_hyphen_window};

#[test]
fn u1_join_split_keywords_exact_outputs() {
    let j = join_split_keywords;
    assert_eq!(j("pa ssword = x").as_deref(), Some("password = x"));
    assert_eq!(
        j("Pa ssword = x").as_deref(),
        Some("password = x"),
        "case is folded into the keyword"
    );
    assert_eq!(j("pa ss word").as_deref(), Some("password"), "two cuts");
    assert_eq!(j("p a s sword"), None, "three cuts are too many");
    assert_eq!(j("password"), None, "nothing to join");
    assert_eq!(j("pass "), None, "a cut at the very end");
    assert_eq!(
        j("pass xord"),
        None,
        "the next letter must continue the keyword"
    );
    assert_eq!(
        j("p assword").as_deref(),
        Some("password"),
        "a cut after the first letter"
    );
    assert_eq!(
        j("pass\u{200b}word").as_deref(),
        Some("password"),
        "zero-width"
    );
    assert_eq!(
        j("pass\u{00ad}word").as_deref(),
        Some("password"),
        "soft hyphen"
    );
    assert_eq!(
        j("é pa ssword é").as_deref(),
        Some("é password é"),
        "multibyte neighbours"
    );
    assert_eq!(j("Bea rer abc").as_deref(), Some("bearer abc"));
    assert_eq!(
        j("to ken, to ken").as_deref(),
        Some("token, token"),
        "every occurrence"
    );
    assert_eq!(
        j("p\u{e9}ssword"),
        None,
        "a non-ASCII letter is not the keyword"
    );
    assert_eq!(
        j(" assword"),
        None,
        "a cut before the first letter does not count"
    );
    assert_eq!(
        j("xpa ssword").as_deref(),
        Some("xpassword"),
        "the keyword may sit inside a longer word"
    );
}

#[test]
fn u2_remove_hyphen_window_exact_outputs() {
    let w = remove_hyphen_window;
    assert_eq!(w("abc-def-ghi-jkl", 3).as_deref(), Some("abcdefghijkl"));
    assert_eq!(
        w("xx abc-def-ghi-jkl", 3).as_deref(),
        Some("xx abcdefghijkl"),
        "a run that starts mid-line"
    );
    assert_eq!(
        w("abc-def-ghi", 3),
        None,
        "two regular hyphens are not enough"
    );
    assert_eq!(
        w("abc-def-ghi-jkl-mno", 3).as_deref(),
        Some("abcdefghijklmno"),
        "the whole run"
    );
    assert_eq!(w("ab-cd-ef-gh", 2).as_deref(), Some("abcdefgh"));
    assert_eq!(
        w("abc-def-gh-jkl", 3),
        None,
        "an irregular position breaks the run"
    );
    assert_eq!(w("", 3), None);
    assert_eq!(
        w("abcde-fgh-ijk-lmn", 3).as_deref(),
        Some("abcdefghijklmn"),
        "a run whose first hyphen is not a multiple of the period"
    );
    assert_eq!(w("ab-cd-ef-gh", 3), None, "a different group size");
    assert_eq!(
        w("é-b-c-d-e-f", 1).as_deref(),
        Some("ébcdef"),
        "multibyte text, period 2"
    );
}

#[test]
fn u3_leaf_expansions_operators_and_bounds() {
    let names = |t: &str, h: bool| {
        leaf_expansions(t, h)
            .into_iter()
            .map(|(c, _)| c.join("+"))
            .collect::<Vec<_>>()
    };
    // a word without a space gets no rot13 or reverse at depth 0
    assert!(names("abcdefghijklmnop", true).is_empty());
    // with a space it gets both, and their compound
    let n = names("alpha beta gamma delta", true);
    assert!(
        n.contains(&"rot13".to_string()) && n.contains(&"reverse".to_string()),
        "{n:?}"
    );
    assert!(n.iter().any(|c| c.starts_with("compound+")), "{n:?}");
    // compounds only up to 1,024 bytes
    let long_ok = "ab ".repeat(341); // 1,023 bytes
    let long_no = "ab ".repeat(342); // 1,026 bytes
    assert!(names(&long_ok, true)
        .iter()
        .any(|c| c.starts_with("compound+")));
    assert!(!names(&long_no, true)
        .iter()
        .any(|c| c.starts_with("compound+")));
    // hyphen candidates: off when the flag is off, off for fewer than three hyphens unless a window or the regular rule fits
    assert!(!names("a-b-c-d-e-f-g-h-i-j", false)
        .iter()
        .any(|c| c.contains("hyphen")));
    assert!(names("a-b-c-d-e-f-g-h-i-j", true)
        .iter()
        .any(|c| c.contains("hyphen")));
    assert!(
        !names("xxxxx-yyyyy zzzz", true)
            .iter()
            .any(|c| c == "hyphen"),
        "one hyphen: no hyphen candidate"
    );
    assert!(
        names("xx-yy-zz word", true)
            .iter()
            .all(|c| !c.ends_with("hyphen") || c == "hyphen"),
        "shape of chains"
    );
    // never more than 24
    let many = "a-b-c-d-e-f ".repeat(30);
    assert!(leaf_expansions(&many, true).len() <= 24);
}

#[test]
fn u4_looks_like_secret_needs_all_three_shapes() {
    assert!(looks_like_secret("Ab3dE6gH9jK2mN5p"));
    assert!(!looks_like_secret("abcdefgh12345678"), "no capital");
    assert!(!looks_like_secret("ABCDEFGH12345678"), "no lowercase");
    assert!(!looks_like_secret("AbcdefghIjklmnop"), "no digit");
    assert!(!looks_like_secret(""));
}

#[test]
fn u5_reference_value_table() {
    let rv = |v: &str| reference_value(v, v);
    // references
    for v in [
        "config.token",
        "self.refresh_token()",
        "os.environ[",
        "std::env::var(",
        "db_api_key_value",
        "dbApiKeyValue",
        "DB_API_KEY",
        "settings.API_KEY_NAME",
        "cfg.Token",
        "ctx->get_token()",
        "ref+vault://x#y",
        "!secret_value_ref",
        "`vault read x`",
        "a_b.c_d",
        "process.env.API_KEY",
        "useAuth().token",
        "Config.Get_Token(x",
    ] {
        assert!(rv(v), "reference: {v}");
    }
    // literals (fail closed)
    for v in [
        "abcdefgh12345678",
        "correcthorse",
        "dbapikeyvalue",
        "DBAPIKEYVALUE",
        "db_api_key_v2",
        "2fa.token_name",
        "config.Ab3dE6gH9jK2mN5pQ7rS9",
        "9fetchtokenvalue(x)",
        "a-b(c)",
        "(cfg.token_value)",
        "a..b.c.d",
        ".config.token",
        "config..token",
        "x.",
        "Ab3dE6gH9jK2mN5p",
    ] {
        assert!(!rv(v), "literal: {v}");
    }
    // a segment of 15 characters with a secret shape is still a path; 16 is a token
    assert!(rv("config.Ab3dE6gH9jK2mN5"));
    assert!(!rv("config.Ab3dE6gH9jK2mN5p"));
    // a call with a quoted literal credential of 16 characters is a literal, with 15 it is a reference; single quotes count; the window is 200 characters
    assert!(!reference_value(
        "get_key(",
        "get_key(\"Ab3dE6gH9jK2mN5p\")"
    ));
    assert!(reference_value("get_key(", "get_key(\"Ab3dE6gH9jK2mN5\")"));
    assert!(!reference_value("get_key(", "get_key('Ab3dE6gH9jK2mN5p')"));
    assert!(
        reference_value("get_key(", "get_key(\"abcdefgh12345678\")"),
        "no capital: a name"
    );
    assert!(
        reference_value("get_key(", "get_key(\"Ab3dE6gH9jK2mN5p qq\")"),
        "a space is not a token character"
    );
    let far = format!("get_key({}\"Ab3dE6gH9jK2mN5p\")", " ".repeat(300));
    assert!(
        reference_value("get_key(", &far),
        "beyond the 200-character window"
    );
}
