//! EG1b mutation triage, batch G: the decoders of the decoded view (`views::decoded`). The encodings below were produced by Python's standard library
//! (base64, base32, hex, rot13), NOT by this crate. Boundaries: base64 and rot13 from 12 characters, base32 and hex from 16 (hex also even and with an optional 0x);
//! a decoded text must be at least 90 percent printable (bytes of 0x80 and above count as printable); decoding repeats to depth 3 and no further.
//! Equivalent mutants (argued in a stage record (not published)): the alphabet test of `b64_decode` (the decoder itself refuses every character outside the alphabet),
//! `bits << 5 | v` to `^` in `b32_decode` (the low five bits of the shifted value are zero), and `text.len() > budget` to `>=` (the expansion budget is four times
//! the input plus 1,024 bytes and a decoding is never that large).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::views::decoded;

const B64_12: &str = "MTIzNDU2Nzg5";
const B64_16: &str = "aGVsbG8gd29ybGQh";
const B64_PLUS: &str = "YWI+P2NkPj9lZj4/";
const B64_URL: &str = "YWI-P2NkPj9lZj4_";
const B64_11: &str = "MTIzNDU2Nzg";
const B32_16: &str = "JBSWY3DPK5XXE3DE";
const B32_15: &str = "JBSWY3DPK5XXE3D";
const HEX_16: &str = "4142434445464748";
const HEX_32: &str = "48656c6c6f20576f726c643132333435";
const HEX_14: &str = "41424344454647";
const ROT13_KEY: &str = "NXVNVBFSBQAA7RKNZCYR";
const ROT13_LOW: &str = "nopqrstuvwxyzabcdefghijklm";
const ROT13_UP: &str = "NOPQRSTUVWXYZABCDEFGHIJKLM";
const ROT13_12: &str = "nopqrstuvwxy";
const B64_HIGH: &str = "YWJjZGVmZ2hpasOp";
const B64_1BAD: &str = "YWJjZGVmZ2hpagFr";
const B64_2BAD: &str = "YWJjZGVmZ2hpAQJr";
const B64_NESTED2: &str = "YUdWc2JHOGdkMjl5YkdRZ2NHRjViRzloWkE9PQ==";
const B64_NESTED3: &str = "WVVkV2MySkhPR2RrTWpsNVlrZFJaMk5IUmpWaVJ6bG9Xa0U5UFE9PQ==";
const B64_NESTED4: &str =
    "V1ZWa1YyTXlTa2hQUjJSclRXcHNOVmxyWkZKYU1rNUlVbXBXYVZKNmJHOVhhMFU1VUZFOVBRPT0=";

fn chains(raw: &str) -> Vec<(Vec<&'static str>, String)> {
    decoded(raw)
        .into_iter()
        .map(|d| (d.chain, d.text))
        .collect()
}
fn has(raw: &str, chain: &[&str], text: &str) -> bool {
    chains(raw).iter().any(|(c, t)| c == chain && t == text)
}
fn any_chain(raw: &str, name: &str) -> bool {
    chains(raw).iter().any(|(c, _)| c.first() == Some(&name))
}

#[test]
fn g1_base64_from_twelve_characters_in_both_alphabets() {
    assert!(
        has(B64_12, &["base64"], "123456789"),
        "12 characters decode"
    );
    assert!(!any_chain(B64_11, "base64"), "11 characters do not");
    assert!(has(B64_16, &["base64"], "hello world!"));
    assert!(
        has(B64_PLUS, &["base64"], "ab>?cd>?ef>?"),
        "the standard alphabet with + and /"
    );
    assert!(
        has(B64_URL, &["base64"], "ab>?cd>?ef>?"),
        "the URL alphabet with - and _"
    );
    // the source span of a decoded text is the token it came from
    let d = decoded(&format!("x {B64_16} y"));
    assert!(
        d.iter()
            .any(|d| d.src == (2, 18) && d.text == "hello world!"),
        "{:?}",
        d.iter().map(|d| d.src).collect::<Vec<_>>()
    );
    // padding characters are tolerated
    assert!(
        has(B64_NESTED2, &["base64"], "aGVsbG8gd29ybGQgcGF5bG9hZA==")
            || has(B64_NESTED2, &["base64"], "aGVsbG8gd29ybGQgcGF5bG9hZA==")
    );
}

#[test]
fn g2_base32_and_hex_from_sixteen_characters() {
    assert!(has(B32_16, &["base32"], "HelloWorld"));
    assert!(
        has(&B32_16.to_lowercase(), &["base32"], "HelloWorld"),
        "lower case is the same encoding"
    );
    assert!(!any_chain(B32_15, "base32"), "15 characters do not decode");
    assert!(
        has(HEX_16, &["hex"], "ABCDEFGH"),
        "exactly 16 hex characters"
    );
    assert!(has(HEX_32, &["hex"], "Hello World12345"));
    assert!(
        has(&format!("0x{HEX_16}"), &["hex"], "ABCDEFGH"),
        "an optional 0x prefix"
    );
    assert!(
        has(&HEX_32.to_uppercase(), &["hex"], "Hello World12345"),
        "upper-case digits"
    );
    assert!(!any_chain(HEX_14, "hex"), "14 characters are too short");
    assert!(
        !any_chain(&format!("{HEX_16}1"), "hex"),
        "an odd number of digits is not hex bytes"
    );
    assert!(
        !any_chain("zz42434445464748", "hex"),
        "a character outside the hex alphabet"
    );
}

#[test]
fn g3_rot13_maps_every_letter_and_needs_twelve_characters_and_a_letter() {
    assert!(
        has(ROT13_KEY, &["rot13"], "AKIAIOSFODNN7EXAMPLE"),
        "digits stay, letters move 13"
    );
    assert!(has(ROT13_LOW, &["rot13"], "abcdefghijklmnopqrstuvwxyz"));
    assert!(has(ROT13_UP, &["rot13"], "ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    assert!(
        has(ROT13_12, &["rot13"], "abcdefghijkl"),
        "exactly twelve characters"
    );
    assert!(!any_chain("nopqrstuvwx", "rot13"), "eleven characters");
    assert!(!any_chain("123456789012", "rot13"), "no letter at all");
    // reverse needs twelve characters too, and keeps every character
    assert!(has("abcdefghijkl", &["reverse"], "lkjihgfedcba"));
    assert!(!any_chain("abcdefghijk", "reverse"));
}

#[test]
fn g4_a_decoded_text_must_be_at_least_ninety_percent_printable() {
    assert!(
        has(B64_HIGH, &["base64"], "abcdefghij\u{e9}"),
        "bytes of 0x80 and above count as printable"
    );
    assert!(
        any_chain(B64_1BAD, "base64"),
        "11 of 12 bytes printable is above 90 percent"
    );
    assert!(
        !any_chain(B64_2BAD, "base64"),
        "10 of 12 is below 90 percent"
    );
}

#[test]
fn g5_decoding_repeats_to_depth_three_and_stops() {
    assert!(
        has(B64_NESTED2, &["base64", "base64"], "hello world payload"),
        "two layers"
    );
    assert!(
        has(
            B64_NESTED3,
            &["base64", "base64", "base64"],
            "hello world payload"
        ),
        "three layers"
    );
    assert!(
        !chains(B64_NESTED4)
            .iter()
            .any(|(c, t)| c.len() == 4 || t == "hello world payload"),
        "four layers are beyond the depth limit"
    );
    // rot13 applies to the raw token only, never to a decoded text
    assert!(
        !chains(B64_16)
            .iter()
            .any(|(c, _)| c.iter().skip(1).any(|n| *n == "rot13")),
        "rot13 is a first-step decoder only"
    );
}
