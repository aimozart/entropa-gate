//! EG1b mutation triage, cluster 2: `decide::plausible_chunked`, the guard that decides whether a stripped-view key or card match is a token cut into
//! regular short groups (a stage record (not published)). The expected value of every row is derived by hand from the written rule, not from the code:
//! a text with no whitespace passes; otherwise every piece (letters or digits between separators) has at most 6 characters, every separator run at most 2,
//! the text does not start with a separator, and, among the pieces between the first and the last, three CONSECUTIVE ones share one length of 3 or more.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::decide::plausible_chunked;

#[test]
fn k1_regular_groups_are_accepted() {
    for (t, why) in [
        (
            "sk- abc def ghi jkl",
            "prefix, then three groups of three in a row",
        ),
        (
            "ab cdefgh ijklmn opqrst uvwxyz qr",
            "groups of exactly six are allowed",
        ),
        (
            "ab, cde, fgh, ijk, lm",
            "separator runs of exactly two characters are allowed",
        ),
        ("ab-cde.fgh_ijk kl", "mixed one-character separators"),
        (
            "a bc def ghi jkl m",
            "the regular window is at the end of the inner pieces",
        ),
        (
            "ab cde fgh ijk lm",
            "five pieces, three equal in the middle",
        ),
    ] {
        assert!(plausible_chunked(t), "{t:?} should be accepted: {why}");
    }
    // no whitespace at all: the stripped view added nothing, so the match is the token itself
    for t in ["sk_live_abcdefghijklmnop", "AKIAIOSFODNN7EXAMPLE", "x"] {
        assert!(plausible_chunked(t), "{t:?} has no whitespace");
    }
}

#[test]
fn k2_prose_and_irregular_text_is_refused() {
    for (t, why) in [
        (" abc def ghi jkl mno", "starts with a separator"),
        (".abc def ghi jkl mno", "starts with a separator (a dot)"),
        ("ab cde fgh ijk lmnopqr", "a piece of seven characters"),
        ("ab cdefghi jkl mno pq", "a piece of seven characters in the middle"),
        ("ab cde   fgh ijk lm", "a separator run of three"),
        ("ab cde fgh ijk", "only two inner pieces"),
        ("ab cd ef gh ij", "three equal inner pieces but of length two"),
        ("ab cde fgh ijkl mn", "inner lengths 3, 3, 4"),
        ("ab cdef ghi jkl mn", "inner lengths 4, 3, 3"),
        ("ab cde fghi jkl mn", "inner lengths 3, 4, 3"),
        ("abc def ghi", "two separators but too few pieces to be regular"),
        ("abc def ghi jk lm no", "the equal groups are the first ones, which do not count (the first piece is outside the window)"),
        ("", "empty"),
        ("a b c d e f", "single letters"),
    ] {
        assert!(!plausible_chunked(t), "{t:?} should be refused: {why}");
    }
}

#[test]
fn k3_the_limits_are_exact() {
    // piece length: 6 passes, 7 does not (in the first, a middle and the last position)
    assert!(plausible_chunked("ab cdefgh ijklmn opqrst uvwxyz qr"));
    assert!(!plausible_chunked("abcdefg hi jkl mno pqr st"));
    assert!(!plausible_chunked("ab cde fgh ijk lmnopqr"));
    // separator run: 2 passes, 3 does not
    assert!(
        plausible_chunked("ab, cde, fgh, ijk, lm"),
        "comma and space is a run of two"
    );
    assert!(
        !plausible_chunked("ab,  cde, fgh, ijk, lm"),
        "comma and two spaces is a run of three"
    );
    // regular length: 3 passes, 2 does not
    assert!(plausible_chunked("ab cde fgh ijk lm"));
    assert!(!plausible_chunked("ab cd ef gh ij"));
}
