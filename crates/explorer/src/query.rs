//! Strict query parsing: only known parameters, each at most once, with plain-ASCII values.

/// Why a query is refused (the answer never says more than "bad request").
pub(crate) struct BadQuery;

/// Parse `a=b&c=d` against the allowed names. Anything else is refused: empty parts, a missing `=`,
/// empty names or values, repeated names, unknown names, and any byte outside `[A-Za-z0-9._-]`
/// (so no percent escapes, no `+`, no unicode, no control characters).
pub(crate) fn parse<'a>(
    query: &'a str,
    allowed: &[&str],
) -> Result<Vec<(&'a str, &'a str)>, BadQuery> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    if query.is_empty() {
        return Ok(out);
    }
    for part in query.split('&') {
        let (k, v) = part.split_once('=').ok_or(BadQuery)?;
        let plain = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        };
        if !plain(k) || !plain(v) || !allowed.contains(&k) || out.iter().any(|(seen, _)| *seen == k)
        {
            return Err(BadQuery);
        }
        out.push((k, v));
    }
    Ok(out)
}

/// The value of `name`, if present.
pub(crate) fn get<'a>(q: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    q.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
}

/// A plain decimal: digits only, no leading zero (except `0` itself), at most 16 digits.
pub(crate) fn decimal(s: &str) -> Option<u64> {
    if s.is_empty()
        || s.len() > 16
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// Largest cursor (2^53 - 1, what a JavaScript client can hold exactly).
pub(crate) const MAX_CURSOR: u64 = (1 << 53) - 1;

#[cfg(test)]
mod tests {
    use super::*;

    const NAMES: [&str; 2] = ["limit", "cursor"];

    #[test]
    fn parse_accepts_known_plain_pairs_once_each() {
        let got = parse("limit=5&cursor=9", &NAMES).ok().unwrap_or_default();
        assert_eq!(got, vec![("limit", "5"), ("cursor", "9")]);
        assert!(parse("", &NAMES).is_ok_and(|v| v.is_empty()));
        assert!(parse("limit=a.b_c-d", &NAMES).is_ok());
    }

    #[test]
    fn parse_refuses_each_kind_of_bad_part_on_its_own() {
        for bad in [
            "limit=5%30",
            "limit=5+",
            "limit=\u{0661}",
            "limit=a b",
            "limit=",
            "limit",
            "=5",
            "limit=5&",
            "&limit=5",
            "limit=5&limit=6",
            "other=5",
            "limit=5&other=6",
            "lim\u{00ef}t=5",
            "li%6dit=5",
            "limit=5;cursor=1",
        ] {
            assert!(parse(bad, &NAMES).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn decimal_is_plain_digits_without_leading_zero_up_to_sixteen() {
        assert_eq!(decimal("0"), Some(0));
        assert_eq!(decimal("7"), Some(7));
        assert_eq!(decimal("1234567890123456"), Some(1_234_567_890_123_456));
        for bad in [
            "",
            "00",
            "01",
            "12345678901234567",
            "1a",
            "a1",
            "-1",
            "+1",
            "1.5",
            " 1",
            "\u{0661}",
        ] {
            assert_eq!(decimal(bad), None, "{bad:?}");
        }
    }
}
