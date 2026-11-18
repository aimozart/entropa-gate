//! AT1 task 2 (red first): the strict reader and the canonical writer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_tokens::canon::{parse, write, CanonError, Json};

#[test]
fn k1_write_sorts_keys_and_has_no_whitespace() {
    let j = parse(br#"{"b":1,"a":[2,3],"c":{"y":true,"x":null}}"#).unwrap();
    assert_eq!(
        write(&j),
        br#"{"a":[2,3],"b":1,"c":{"x":null,"y":true}}"#.to_vec()
    );
}

#[test]
fn k2_the_strict_reader_refuses_everything_that_is_not_canonical_input() {
    for bad in [
        &br#"{"a":1,"a":2}"#[..],
        br#"{"a":1.5}"#,
        br#"{"a":01}"#,
        br#"{"a":-1}"#,
        br#"{"a":1e3}"#,
        br#"{"a" : 1}"#,
        br#" {"a":1}"#,
        br#"{"a":1} "#,
        br#"{"a":"\u0041"}"#,
        b"{\"a\":\"\xff\"}",
        b"{\"a\":\"line\nbreak\"}",
        br#"{"a":18446744073709551616}"#,
        br#"{"a":1,}"#,
        br#"[1,2"#,
        b"",
        b"\xef\xbb\xbf{}",
    ] {
        assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
    }
    assert_eq!(
        parse(br#"{"a":1,"a":2}"#).unwrap_err(),
        CanonError::DuplicateKey
    );
}

#[test]
fn k3_depth_and_size_are_bounded() {
    let deep = format!("{}{}", "[".repeat(100), "]".repeat(100));
    assert!(parse(deep.as_bytes()).is_err());
    let big = format!("[{}0]", "0,".repeat(200_000));
    assert!(parse(big.as_bytes()).is_err());
}

#[test]
fn k4_what_is_written_is_what_parses_back() {
    let j = Json::Object(vec![
        ("z".into(), Json::Num(u64::MAX)),
        ("a".into(), Json::Str("x\"y\\z".into())),
        ("m".into(), Json::Array(vec![Json::Bool(false), Json::Null])),
    ]);
    let bytes = write(&j);
    assert_eq!(write(&parse(&bytes).unwrap()), bytes);
}
