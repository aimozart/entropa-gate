//! HARDENING (a stage record (not published)): the audit found 76 `indexing_slicing` sites (66 indexing, 10 slicing) in non-test code of `entropa-egress`; this test drives `decide` with 400,000 structured hostile strings (fragments chosen to
//! sit exactly where those indexes and slices live: truncated percent escapes, a keyword cut at the end, multibyte characters next to separators, digit runs at the end, base64 and PEM stubs, 4 to 6 character
//! credential words with every separator) and requires that NOTHING panics. Deterministic (xorshift, fixed seed); synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::decide;
use entropa_egress::policy::Tier;

const FRAGMENTS: &[&str] = &[
    "password",
    "pass-word",
    "pa-ss-wo-rd",
    "secret_key",
    "api_key",
    "token",
    "Bearer ",
    "Bearer",
    "Authorization: ",
    "curl -u ",
    "curl -H ",
    "export ",
    "=",
    ":",
    ":=",
    " = ",
    "\"",
    "'",
    "`",
    "(",
    ")",
    "((",
    "))",
    "%",
    "%4",
    "%41",
    "%zz",
    "%2",
    "%2F",
    "&",
    "<",
    ">",
    "{{",
    "}}",
    "${",
    "$(",
    "$",
    "$$",
    "!",
    "!!",
    "-",
    "_",
    ".",
    "/",
    "\\",
    ";",
    ",",
    " ",
    "\t",
    "\n",
    "\r\n",
    "é",
    "ü",
    "日本",
    "\u{1F600}",
    "\u{202e}",
    "\u{200b}",
    "\u{0}",
    "\u{7f}",
    "ｐａｓｓ",
    "İ",
    "ß",
    "1",
    "12",
    "123456789",
    "4111111111111111",
    "411111111111 1111",
    "4111-1111-1111-1111",
    "912-00-3456",
    "912 00 3456",
    "1234567890123456789012345",
    "0000000000",
    "AKIA",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "eyJ",
    "eyJhbGciOiJIUzI1NiJ9.",
    ".",
    "sk-",
    "sk-abcdefghijklmnopqrstuvwxyz",
    "-----BEGIN PRIVATE KEY-----",
    "-----END PRIVATE KEY-----",
    "MIIB",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
    "AAAA",
    "====",
    "A==",
    "Zm9v",
    "Zm9vYg==",
    "%41%42%43%44%45%46%47%48%49%4a%4b%4c%4d%4e",
    "%70%61%73%73%77%6f%72%64%3d%58%6b%39%51%7a%4c%32",
    "deadbeefdeadbeefdeadbeef",
    "0x70617373776f72643d58",
    "UGFzc3dvcmQ9WGs5UXpMMg==",
    "UGFzc3dvcmQ9WGs5UXpMMg",
    "cGFzc3dvcmQ9",
    "\\u0070\\u0061\\u0073\\u0073",
    "&#x70;&#x61;&#115;&#115;",
    "&amp;",
    "cGFzc3dvcmQ9WGs5UXpMMjk4N2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6",
    "drowssap",
    "cnffjbeq",
    "ENTROPA-CANARY-",
    "0123456789abcdef",
    "http://",
    "https://example.invalid/",
    "user@example.invalid",
    "5551234",
    "(555) 010-0100",
];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn gen(r: &mut Rng) -> String {
    let n = 1 + r.below(24);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(FRAGMENTS[r.below(FRAGMENTS.len())]);
    }
    // cut anywhere on a character boundary: a truncated tail is where indexing goes wrong
    if r.below(3) == 0 && !s.is_empty() {
        let mut k = r.below(s.len() + 1);
        while !s.is_char_boundary(k) {
            k -= 1;
        }
        s.truncate(k);
    }
    s
}

#[test]
fn h1_four_hundred_thousand_hostile_strings_never_panic_in_any_tier() {
    let (pol, cv, mem) = (policy(), conv(), Mem::new());
    let mut r = Rng(0x9E37_79B9_7F4A_7C15);
    let mut panics = Vec::new();
    for i in 0..400_000u32 {
        let s = gen(&mut r);
        let tier = [Tier::T0, Tier::T1, Tier::T2, Tier::T3][(i % 4) as usize];
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = decide(&text_req(&s), &pol, tier, &cv, &mem);
        }));
        if res.is_err() && panics.len() < 5 {
            panics.push(s);
        }
    }
    assert!(panics.is_empty(), "panics on: {panics:?}");
}

#[test]
fn h2_the_public_view_functions_never_panic_on_the_same_strings() {
    use entropa_egress::views::{
        decoded, fold, join_split_keywords, leaf_expansions, remove_hyphen_window,
        remove_separators, remove_separators_keep_spaces, strip,
    };
    let mut r = Rng(0xD1B5_4A32_D192_ED03);
    let mut panics = Vec::new();
    for _ in 0..300_000u32 {
        let s = gen(&mut r);
        let res = std::panic::catch_unwind(|| {
            let _ = decoded(&s);
            let _ = leaf_expansions(&s, true);
            let _ = leaf_expansions(&s, false);
            let _ = join_split_keywords(&s);
            let _ = remove_separators(&s);
            let _ = remove_separators_keep_spaces(&s);
            let _ = remove_hyphen_window(&s, 3);
            let _ = remove_hyphen_window(&s, 6);
            let _ = fold(&s);
            let _ = strip(&s);
        });
        if res.is_err() && panics.len() < 5 {
            panics.push(s);
        }
    }
    assert!(panics.is_empty(), "panics on: {panics:?}");
}
