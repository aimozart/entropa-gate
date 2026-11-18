//! The detectors D1 to D8: deterministic, linear-time scanners over one view of a text. No learned component, no network, no clock.
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Detector ids (closed). Order is the order of the closed list in the policy and in records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs)]
pub enum Det {
    D1,
    D2,
    D3,
    D4,
    D5Id,
    D5Email,
    D5Phone,
    D5Dob,
    D6,
    D7,
    D8,
}

impl Det {
    /// Every id, in order.
    pub const ALL: &'static [Det] = &[
        Det::D1,
        Det::D2,
        Det::D3,
        Det::D4,
        Det::D5Id,
        Det::D5Email,
        Det::D5Phone,
        Det::D5Dob,
        Det::D6,
        Det::D7,
        Det::D8,
    ];
    /// The wire id.
    pub fn as_str(self) -> &'static str {
        match self {
            Det::D1 => "D1",
            Det::D2 => "D2",
            Det::D3 => "D3",
            Det::D4 => "D4",
            Det::D5Id => "D5.id",
            Det::D5Email => "D5.email",
            Det::D5Phone => "D5.phone",
            Det::D5Dob => "D5.dob",
            Det::D6 => "D6",
            Det::D7 => "D7",
            Det::D8 => "D8",
        }
    }
    /// Parse a wire id; `None` outside the closed list.
    pub fn parse(s: &str) -> Option<Det> {
        Det::ALL.iter().copied().find(|d| d.as_str() == s)
    }
}

/// The kind of view a text is, which decides which detectors run (a stripped view has no word boundaries and no case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs)]
pub enum ViewKind {
    Raw,
    Folded,
    Stripped,
    Decoded,
    /// A rot13 or reversed token: only the secret and structure detectors run (a reversed email-shaped string is noise).
    Obfuscated,
}
impl ViewKind {
    /// The wire id.
    pub fn as_str(self) -> &'static str {
        match self {
            ViewKind::Raw => "raw",
            ViewKind::Folded => "folded",
            ViewKind::Stripped => "stripped",
            ViewKind::Decoded => "decoded",
            ViewKind::Obfuscated => "decoded",
        }
    }
}

/// A client do-not-send term: literal words (never a pattern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    /// The words or phrases.
    pub words: Vec<String>,
    /// Match whole words only.
    pub whole_word: bool,
    /// All words must be present (co-occurrence); otherwise any one.
    pub all: bool,
}

/// What the detectors need from the policy.
#[derive(Debug, Clone, Default)]
pub struct DetectCfg {
    /// D7 terms.
    pub terms: Vec<Term>,
    /// D8 banner phrases.
    pub markers: Vec<String>,
    /// D8 keyed-marker key.
    pub marker_key: Vec<u8>,
    /// D1 published example strings that are allowed (exact, case-insensitive).
    pub examples: Vec<String>,
}

/// One match: byte range in the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The detector.
    pub det: Det,
    /// Start byte.
    pub start: usize,
    /// End byte.
    pub end: usize,
    /// A format checksum was present and held (or a structure rule held).
    pub checksum_ok: bool,
}

struct Rx {
    aws: Regex,
    github: Regex,
    slack: Regex,
    stripe: Regex,
    openai: Regex,
    google: Regex,
    npm: Regex,
    hook: Regex,
    pem: Regex,
    putty: Regex,
    jwk_d: Regex,
    jwt: Regex,
    auth: Regex,
    bearer: Regex,
    hyrun: Regex,
    conn: Regex,
    assign: Regex,
    lit_call: Regex,
    assign_call: Regex,
    curl_user: Regex,
    ssn: Regex,
    nhs: Regex,
    nino: Regex,
    iban: Regex,
    email: Regex,
    e164: Regex,
    nanp: Regex,
    dob: Regex,
    ent: Regex,
    mark: Regex,
    b64tok: Regex,
}

fn rx(bounded: bool) -> &'static Rx {
    static B: OnceLock<Rx> = OnceLock::new();
    static U: OnceLock<Rx> = OnceLock::new();
    let cell = if bounded { &B } else { &U };
    cell.get_or_init(|| {
        let b = if bounded { r"\b" } else { "" };
        let r = |p: String| Regex::new(&p).unwrap_or_else(|_| Regex::new("$^").unwrap_or_else(|_| unreachable_regex()));
        Rx {
            // 16 upper-case alphanumerics as EG0 says (real ids are base32, A-Z2-7, but a guard that errs toward block also stops 0, 1, 8 and 9: EG1b)
            aws: r(format!(r"(?i){b}(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{{16}}{b}")),
            // a stripped view has lost its underscores and hyphens, so the prefixed forms are matched without them (the caller then
            // requires the raw span to look like a chunked token, see `decide::plausible_chunked`)
            github: r(if bounded { format!(r"(?i){b}gh[pousr]_[A-Za-z0-9]{{36,255}}{b}") } else { "gh[pousr][a-z0-9]{36,255}".to_string() }),
            slack: r(if bounded { format!(r"(?i){b}xox[abprs]-[a-z0-9-]{{10,}}") } else { "xox[abprs][a-z0-9]{20,}".to_string() }),
            stripe: r(if bounded { format!(r"(?i){b}[sr]k_(?:live|test)_[a-z0-9]{{16,}}") } else { "[sr]k(?:live|test)[a-z0-9]{16,}".to_string() }),
            openai: r(if bounded { format!(r"(?i){b}sk-[a-z0-9_-]{{32,}}") } else { "sk[a-z0-9]{32,}".to_string() }),
            google: r(format!(r"(?i){b}AIza[0-9A-Za-z_-]{{35,60}}")),
            npm: r(if bounded { format!(r"(?i){b}npm_[a-z0-9]{{36}}{b}") } else { "npm[a-z0-9]{36}".to_string() }),
            hook: r(r"(?i)hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+".to_string()),
            pem: r(r"(?i)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----".to_string()),
            putty: r(r"(?i)PuTTY-User-Key-File-\d".to_string()),
            jwk_d: r(r#"(?i)"(?:d|p|q|dp|dq|qi)"\s*:\s*"[A-Za-z0-9_-]{8,}""#.to_string()),
            jwt: r(r"(?i)\beyJ[a-z0-9_-]{4,}\.[a-z0-9_-]{4,}\.[a-z0-9_-]*".to_string()),
            auth: r(r#"(?i)\bauthorization\s*:\s*(?:bearer|basic|token)\s*([^\s"']{8,})"#.to_string()),
            conn: r(r#"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@"']+:([^\s@/"']+)@"#.to_string()),
            // a bare `Bearer <token>` outside an Authorization header (EG1b, approved by the reviewer 2026-11-14): the caller requires 20+ characters with a letter and a digit
            bearer: r(r#"(?i)\bbearer\s+([^\s"']{20,})"#.to_string()),
            // a run that could be a hyphen-grouped token (the hyphens are tested for a regular grouping in `hyphen_grouped_jwt`)
            hyrun: r(r"[A-Za-z0-9._-]{30,}".to_string()),
            // a key word may carry a prefix such as `api_`, `access-` or `DB_`: `\btoken\b` alone has no boundary after an underscore (EG1b)
            // the key word may carry a prefix (`api_`, `DB_`, camelCase `dbPassword`) and the operator may be `:=` (EG1d)
            assign: r(r#"(?i)\b[a-z0-9_-]*?(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|client[_-]?secret|access[_-]?key)\b["']?[\]}]?\s*(?::=|[:=])\s*\(*\s*(["']?)([^\s"',;]{8,})"#.to_string()),
            // `curl -u user:secret` and `--user user:secret` (EG1e)
            curl_user: r(r#"(?i)\b(?:curl|wget|http)\b[^\n]*?\s(?:-u|--user)[ =]\s*["']?[^\s:"']+:([^\s"']{6,})"#.to_string()),
            // an assignment whose value is a call with a literal credential as its argument (`api_key = get_key("...")`; EG1d)
            assign_call: r(r#"(?i)\b[a-z0-9_-]*?(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|client[_-]?secret|access[_-]?key)\b["']?\s*(?::=|[:=])\s*[a-z_][a-z0-9_.:>-]*\s*\(\s*["']([A-Za-z0-9._~+/=-]{16,})["']"#.to_string()),
            // a literal credential passed to a call whose name holds a key word (`get_credentials("...")`, `load_token("...")`; EG1d)
            lit_call: r(r#"(?i)\b[a-z_][a-z0-9_.]*(?:secret|token|password|passwd|credentials?|api[_-]?key|apikey|access[_-]?key)[a-z0-9_]*\s*\(\s*["']([A-Za-z0-9._~+/=-]{16,})["']"#.to_string()),
            ssn: r(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b".to_string()),
            nhs: r(r"(?i)(?P<kw>nhs\D{0,12})?(?P<num>\b\d{3}[ -]?\d{3}[ -]?\d{4}\b)".to_string()),
            nino: r(r"(?i)\b[a-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[a-d]\b".to_string()),
            iban: r(r"(?i)\b[a-z]{2}\d{2}(?: ?[a-z0-9]){11,30}".to_string()),
            email: r(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b".to_string()),
            e164: r(r"\+\d[\d ()-]{6,17}\d".to_string()),
            nanp: r(r"(?:\(\d{3}\)\s?|\b\d{3}[-. ])\d{3}[-. ]\d{4}\b".to_string()),
            dob: r(r"(?i)\b(?:dob|d\.o\.b\.?|date of birth|born(?: on)?|birth ?date)\b\W{0,4}(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4}|\d{1,2}\.\d{1,2}\.\d{4})".to_string()),
            ent: r(r"[A-Za-z0-9+/_=-]{24,}".to_string()),
            mark: r(r"(?i)\bEGM-([0-9a-f]{8})-([0-9a-f]{8})\b".to_string()),
            b64tok: r(r"[A-Za-z0-9+/]{100,}={0,2}".to_string()),
        }
    })
}

fn unreachable_regex() -> Regex {
    // an empty pattern always compiles; only used if a built-in pattern above were invalid
    Regex::new("").unwrap_or_else(|_| unreachable_regex())
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for b in data {
        c ^= *b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}
fn base62_6(mut n: u64) -> String {
    let al = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut v = Vec::new();
    for _ in 0..6 {
        v.push(al[(n % 62) as usize]);
        n /= 62;
    }
    v.reverse();
    String::from_utf8_lossy(&v).into_owned()
}
fn luhn(d: &[u8]) -> bool {
    let mut sum = 0;
    for (i, x) in d.iter().rev().enumerate() {
        let mut v = (x - b'0') as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}
fn card_issuer(d: &[u8]) -> bool {
    let s = String::from_utf8_lossy(d);
    let n = d.len();
    let p = |k: usize| s[..k].parse::<u32>().unwrap_or(0);
    (s.starts_with('4') && matches!(n, 13 | 16 | 19))
        || (n == 16 && ((51..=55).contains(&p(2)) || (2221..=2720).contains(&p(4))))
        || (n == 15 && matches!(p(2), 34 | 37))
        || ((16..=19).contains(&n) && (p(4) == 6011 || p(2) == 65 || (644..=649).contains(&p(3))))
        || ((16..=19).contains(&n) && (3528..=3589).contains(&p(4)))
        || ((14..=19).contains(&n) && ((300..=305).contains(&p(3)) || matches!(p(2), 36 | 38)))
        || ((16..=19).contains(&n) && p(2) == 62)
}
fn iban_len(cc: &str) -> Option<usize> {
    Some(match cc {
        "AD" => 24,
        "AT" => 20,
        "BE" => 16,
        "BG" => 22,
        "CH" => 21,
        "CY" => 28,
        "CZ" => 24,
        "DE" => 22,
        "DK" => 18,
        "EE" => 20,
        "ES" => 24,
        "FI" => 18,
        "FR" => 27,
        "GB" => 22,
        "GR" => 27,
        "HR" => 21,
        "HU" => 28,
        "IE" => 22,
        "IS" => 26,
        "IT" => 27,
        "LI" => 21,
        "LT" => 20,
        "LU" => 20,
        "LV" => 21,
        "MC" => 27,
        "MT" => 31,
        "NL" => 18,
        "NO" => 15,
        "PL" => 28,
        "PT" => 25,
        "RO" => 24,
        "SE" => 24,
        "SI" => 19,
        "SK" => 24,
        "SM" => 27,
        _ => return None,
    })
}
/// Is this run a JWT with a hyphen inserted after every `g` characters (g from 3 to 8)? The hyphens at the regular positions are removed and
/// the result must be a JWT whose header decodes to JSON with `alg`. A hyphen that is part of the base64url text lies off the regular
/// positions, so it stays; a run whose regular positions are not all hyphens is not tried for that `g`.
fn hyphen_grouped_jwt(run: &str, r: &Rx) -> bool {
    let b = run.as_bytes();
    (3..=8usize).any(|g| {
        let mut out = Vec::with_capacity(b.len());
        for (i, &c) in b.iter().enumerate() {
            if (i + 1) % (g + 1) == 0 {
                if c != b'-' {
                    return false;
                }
            } else {
                out.push(c);
            }
        }
        let Ok(t) = String::from_utf8(out) else {
            return false;
        };
        r.jwt.find(&t).is_some_and(|m| {
            m.start() == 0 && b64url_json_has_alg(m.as_str().split('.').next().unwrap_or(""))
        })
    })
}
fn iban_ok(s: &str) -> bool {
    // an IBAN is ASCII; text that only matched through a Unicode case look-alike is not one (and byte slicing it could panic)
    if !s.is_ascii() || s.len() < 4 {
        return false;
    }
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut rem = 0u32;
    for c in rearranged.chars() {
        let v = if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else {
            c.to_ascii_uppercase() as u32 - 'A' as u32 + 10
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}
fn nhs_ok(d: &[u8]) -> bool {
    if d.len() != 10 {
        return false;
    }
    let sum: u32 = d[..9]
        .iter()
        .enumerate()
        .map(|(i, x)| (x - b'0') as u32 * (10 - i as u32))
        .sum();
    let c = 11 - (sum % 11);
    let c = if c == 11 { 0 } else { c };
    c != 10 && c == (d[9] - b'0') as u32
}
/// A YAML tag such as `!secret` or `!vault`: an exclamation mark and a plain word (a value that merely starts with `!` is a secret).
fn yaml_tag(v: &str) -> bool {
    v.strip_prefix('!').is_some_and(|w| {
        (2..=16).contains(&w.len()) && w.chars().all(|c| c.is_ascii_alphabetic() || c == '_')
    })
}

/// After `Bearer`: a template (`${X}`, `$(cmd)`, `{{x}}`, `<x>`, `%(x)s`) or a shell variable (`$NAME`: a dollar sign and ONLY identifier characters) is not a credential; a value that merely STARTS with a
/// symbol (`$999A&A!9...`, `*99Aa...`) is (round 4: symbol-rich values leaked).
fn bearer_placeholder(v: &str) -> bool {
    if v.starts_with("${")
        || v.starts_with("$(")
        || v.starts_with("{{")
        || v.starts_with('<')
        || v.starts_with("%(")
    {
        return true;
    }
    match v.strip_prefix('$') {
        Some(rest) => {
            rest.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => placeholder(v),
    }
}

/// EG1e (the reviewer's D1 to D3, 2026-11-16): is `v`, the value found after a credential key, a literal credential? A QUOTED value is a literal in every language unless it is a placeholder
/// (tight rule: after stripping placeholder words, separators and digits nothing of four or more characters remains); an UNQUOTED value in a key-value line (`key: value`, `export KEY=value`,
/// `KEY=value` at the start of a line) is a literal unless it is a placeholder or a template reference; an unquoted value after `=` or `:=` in code position is judged by `reference_value`.
fn assign_is_literal(text: &str, start: usize, vstart: usize, quote: &str, v: &str) -> bool {
    // the pattern may have started the value INSIDE a parenthesis (`((a.b.c))` backtracks to `(a.b.c))`): the value is what follows the opening parentheses, and a value shorter than 8 characters is not judged
    let (vstart, v) = (
        vstart + (v.len() - v.trim_start_matches('(').len()),
        v.trim_start_matches('('),
    );
    if v.len() < 8 && quote.is_empty() {
        return false;
    }
    if bearer_placeholder(v) {
        return false;
    }
    if !quote.is_empty() {
        return !placeholder_words_only(v);
    }
    let pre = &text[start..vstart];
    let op_colon = pre.contains(':') && !pre.contains(":=");
    let line_start = text[..start].rsplit('\n').next().unwrap_or("");
    let env_style = !op_colon
        && !pre.contains(char::is_whitespace)
        && (line_start.trim().is_empty() || line_start.trim_end().ends_with("export"));
    if op_colon || env_style {
        // a key-value format has no variables: only a template, a vault reference or a tag is a reference
        return !(v.starts_with("ref+")
            || yaml_tag(v)
            || v.starts_with("{{")
            || v.starts_with('`'));
    }
    !reference_value(v, &text[vstart..])
}

/// The tight placeholder rule for a QUOTED value (D2): lower-case, take out the separators and digits and the placeholder words; a placeholder only when fewer than four characters are left.
fn placeholder_words_only(v: &str) -> bool {
    // digits are NOT stripped (a digit tail is a secret-like tail: `changemeAu07e164` blocks)
    let mut s: String = v
        .to_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    for w in [
        "changeme",
        "placeholder",
        "example",
        "dummy",
        "sample",
        "redacted",
        "xxx",
        "todo",
        "your",
        "here",
        "password",
        "token",
        "secret",
        "key",
        "api",
        "value",
        "replace",
        "insert",
        "enter",
        "name",
    ] {
        s = s.replace(w, "");
    }
    s.len() < 4
}

/// A random-looking token: letters of both cases and a digit (a name, a path or a word never has all three).
pub fn looks_like_secret(t: &str) -> bool {
    t.bytes().any(|b| b.is_ascii_digit())
        && t.bytes().any(|b| b.is_ascii_uppercase())
        && t.bytes().any(|b| b.is_ascii_lowercase())
}
/// EG1d: is the value of an assignment a REFERENCE (a call, a lookup, a path or a variable) rather than a literal credential? `rest` is the text from the value on. Fail closed: a value that
/// matches none of the reference shapes, or a call with a literal-credential-looking quoted argument, is a literal.
pub fn reference_value(v: &str, rest: &str) -> bool {
    let ident = |s: &str| {
        s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let path = |s: &str| {
        !s.is_empty()
            && s.split('.')
                .all(|seg| ident(seg) && !(seg.len() >= 16 && looks_like_secret(seg)))
    };
    if v.starts_with("ref+") || yaml_tag(v) || v.starts_with('`') {
        return true;
    }
    if let Some(i) = v.find(['(', '[']) {
        // a call or an index: the part before it is an identifier path (`os.environ`, `std::env::var`, `self.x`)
        let head = v[..i].replace("::", ".").replace("->", ".");
        if !path(&head) {
            return false;
        }
        // fail closed on a quoted argument that is itself a credential
        let window: String = rest.chars().take(200).collect();
        let mut quoted = window
            .split(['"', '\''])
            .enumerate()
            .filter(|(n, _)| n % 2 == 1)
            .map(|(_, t)| t);
        return !quoted.any(|t| {
            t.len() >= 16
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._~+/=-".contains(&b))
                && looks_like_secret(t)
        });
    }
    if v.contains('.') {
        return path(v.trim_end_matches([')', ';']));
    }
    // a bare variable name: snake_case or camelCase, no digits (a random token has digits); one closing parenthesis of `(name)` is not part of it
    let v = v.trim_end_matches([')', ';']);
    ident(v)
        && !v.bytes().any(|b| b.is_ascii_digit())
        && (v.contains('_')
            || v.as_bytes()
                .windows(2)
                .any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase()))
}
fn placeholder(v: &str) -> bool {
    let l = v.to_lowercase();
    l.starts_with("${")
        || l.starts_with('<')
        || l.starts_with("{{")
        || l.starts_with("$(")
        || l.starts_with("%(")
        || l.starts_with('$')
        || matches!(
            l.as_str(),
            "changeme"
                | "password"
                | "secret"
                | "example"
                | "placeholder"
                | "yourpassword"
                | "redacted"
                | "none"
                | "null"
                | "undefined"
                | "todo"
        )
        || l.chars().all(|c| c == l.chars().next().unwrap_or('x'))
        || l.chars().all(|c| matches!(c, 'x' | '*' | '.'))
}
fn entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = s.chars().count() as f64;
    counts
        .values()
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum()
}
fn b64url_json_has_alg(h: &str) -> bool {
    use base64::Engine;
    let Ok(bytes) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(h.trim_end_matches('='))
    else {
        return false;
    };
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(serde_json::Value::Object(m)) => m.contains_key("alg"),
        _ => false,
    }
}
/// The older private-key layouts that carry no algorithm identifier (EG1b: found with real OpenSSL keys, whose `genpkey` DER output is of this kind):
/// PKCS#1 `RSAPrivateKey` (SEQUENCE, version 0, then the modulus INTEGER with a long-form length) and SEC1 `ECPrivateKey` (SEQUENCE, version 1, then an
/// OCTET STRING of 16 to 66 bytes, the private scalar).
fn der_traditional(b: &[u8]) -> bool {
    let hdr = match b.get(1) {
        Some(&n) if n < 0x80 => 2,
        Some(0x81) => 3,
        Some(0x82) => 4,
        _ => return false,
    };
    let Some(t) = b.get(hdr..hdr + 5) else {
        return false;
    };
    let pkcs1 = t[..4] == [0x02, 0x01, 0x00, 0x02] && matches!(t[4], 0x81 | 0x82);
    let sec1 = t[..4] == [0x02, 0x01, 0x01, 0x04] && (16..=66).contains(&t[4]);
    pkcs1 || sec1
}
fn der_private(b: &[u8]) -> bool {
    if b.len() < 40 || b[0] != 0x30 {
        return false;
    }
    if der_traditional(b) {
        return true;
    }
    let head = &b[..b.len().min(12)];
    let Some(i) = head.windows(4).position(|w| w == [0x02, 0x01, 0x00, 0x30]) else {
        return false;
    };
    let win = &b[i..b.len().min(i + 40)];
    [
        &[
            0x06u8, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ][..],
        &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
        &[0x06, 0x03, 0x2b, 0x65, 0x70],
    ]
    .iter()
    .any(|oid| win.windows(oid.len()).any(|w| w == *oid))
}
fn norm_words(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Scan one raw-kind text with every detector.
pub fn scan(text: &str, cfg: &DetectCfg) -> Vec<Hit> {
    scan_kind(text, ViewKind::Raw, cfg)
}

/// Scan one view. A stripped view runs only the detectors that survive losing separators, case and word boundaries.
pub fn scan_kind(text: &str, kind: ViewKind, cfg: &DetectCfg) -> Vec<Hit> {
    let stripped = kind == ViewKind::Stripped;
    let r = rx(!stripped);
    let mut hits: Vec<Hit> = Vec::new();
    let mut add = |det: Det, s: usize, e: usize, ok: bool| {
        hits.push(Hit {
            det,
            start: s,
            end: e,
            checksum_ok: ok,
        })
    };
    // D1
    for re in [
        &r.aws, &r.slack, &r.stripe, &r.openai, &r.google, &r.npm, &r.hook, &r.github,
    ] {
        for m in re.find_iter(text) {
            let v = m.as_str();
            if cfg.examples.iter().any(|e| e.eq_ignore_ascii_case(v)) {
                continue;
            }
            let mut ok = false;
            if let Some(body) = v.strip_prefix("gh").and_then(|x| x.get(2..)) {
                // `(?i)` also matches non-ASCII look-alikes of ASCII letters (Kelvin sign, long s), so the split must be checked
                if body.len() == 36 {
                    if let Some(tail) = body.get(30..) {
                        ok = base62_6(crc32(&body.as_bytes()[..30]) as u64) == tail;
                    }
                }
            }
            add(Det::D1, m.start(), m.end(), ok);
        }
    }
    if stripped {
        run_stripped_rest(text, cfg, r, &mut hits);
        return dedupe(hits);
    }
    // D2
    for m in r.pem.find_iter(text).chain(r.putty.find_iter(text)) {
        add(Det::D2, m.start(), m.end(), true);
    }
    if text.contains("\"kty\"") {
        for m in r.jwk_d.find_iter(text) {
            add(Det::D2, m.start(), m.end(), true);
        }
    }
    for m in r.b64tok.find_iter(text) {
        use base64::Engine;
        let t = m.as_str().trim_end_matches('=');
        if let Ok(b) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(t) {
            if der_private(&b) {
                add(Det::D2, m.start(), m.end(), true);
            }
        }
    }
    // D3
    for m in r.jwt.find_iter(text) {
        let h = m.as_str().split('.').next().unwrap_or("");
        if b64url_json_has_alg(h) {
            add(Det::D3, m.start(), m.end(), true);
        }
    }
    // EG1e: the value after `Bearer` may hold symbols (`#`, `!`, `^`, `*`, `$`, `&`): any run of non-space, non-quote characters, unless it is a placeholder (`${TOKEN}`, `$TOKEN`, `<token>`, `$(cmd)`)
    for c in r.auth.captures_iter(text) {
        if let (Some(all), Some(v)) = (c.get(0), c.get(1)) {
            if !bearer_placeholder(v.as_str()) {
                add(Det::D3, all.start(), all.end(), true);
            }
        }
    }
    // a bare `Bearer <token>`: 20+ token characters holding a letter and a digit (prose such as "bearer of the message" has neither shape)
    for c in r.bearer.captures_iter(text) {
        if let (Some(all), Some(tok)) = (c.get(0), c.get(1)) {
            let t = tok.as_str();
            if !bearer_placeholder(t)
                && t.bytes().any(|b| b.is_ascii_alphabetic())
                && t.bytes().any(|b| b.is_ascii_digit())
            {
                add(Det::D3, all.start(), all.end(), true);
            }
        }
    }
    // a JWT cut by a hyphen after every few characters (EG1b): only a REGULAR grouping of 3 to 8 characters is recognised, a documented limit
    for m in r.hyrun.find_iter(text) {
        if m.as_str().contains('-') && hyphen_grouped_jwt(m.as_str(), r) {
            add(Det::D3, m.start(), m.end(), true);
        }
    }
    for c in r.conn.captures_iter(text) {
        if let (Some(all), Some(pw)) = (c.get(0), c.get(1)) {
            if pw.as_str().len() >= 3 && !placeholder(pw.as_str()) {
                add(Det::D3, all.start(), all.end(), true);
            }
        }
    }
    for c in r.assign.captures_iter(text) {
        if let (Some(all), Some(q), Some(v)) = (c.get(0), c.get(1), c.get(2)) {
            if assign_is_literal(text, all.start(), v.start(), q.as_str(), v.as_str()) {
                add(Det::D3, all.start(), all.end(), true);
            }
        }
    }
    for c in r.curl_user.captures_iter(text) {
        if let (Some(all), Some(v)) = (c.get(0), c.get(1)) {
            if !bearer_placeholder(v.as_str()) {
                add(Det::D3, all.start(), all.end(), true);
            }
        }
    }
    for c in r.assign_call.captures_iter(text) {
        if let (Some(all), Some(v)) = (c.get(0), c.get(1)) {
            if looks_like_secret(v.as_str()) {
                add(Det::D3, all.start(), all.end(), true);
            }
        }
    }
    for c in r.lit_call.captures_iter(text) {
        if let (Some(all), Some(v)) = (c.get(0), c.get(1)) {
            if looks_like_secret(v.as_str()) {
                add(Det::D3, all.start(), all.end(), true);
            }
        }
    }
    run_stripped_rest(text, cfg, r, &mut hits);
    if kind == ViewKind::Obfuscated {
        return dedupe(hits);
    }
    // D5 (not on a stripped view)
    for m in r.ssn.find_iter(text) {
        let d: Vec<u8> = m.as_str().bytes().filter(u8::is_ascii_digit).collect();
        let area: u32 = String::from_utf8_lossy(&d[..3]).parse().unwrap_or(0);
        let ok =
            !(area == 0 || area == 666 || area >= 900) && &d[3..5] != b"00" && &d[5..] != b"0000";
        hits.push(Hit {
            det: Det::D5Id,
            start: m.start(),
            end: m.end(),
            checksum_ok: ok,
        });
    }
    for c in r.nhs.captures_iter(text) {
        if let Some(m) = c.name("num") {
            let s = m.as_str();
            let d: Vec<u8> = s.bytes().filter(u8::is_ascii_digit).collect();
            let formatted = s.matches([' ', '-']).count() >= 2 || c.name("kw").is_some();
            if formatted && nhs_ok(&d) {
                hits.push(Hit {
                    det: Det::D5Id,
                    start: m.start(),
                    end: m.end(),
                    checksum_ok: true,
                });
            }
        }
    }
    for m in r.nino.find_iter(text) {
        let u: String = m
            .as_str()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_uppercase();
        // the first two CHARACTERS (a Kelvin sign or long s can match `[a-z]` under `(?i)` and is wider than one byte)
        let pre: String = u.chars().take(2).collect();
        if !matches!(pre.as_str(), "BG" | "GB" | "NK" | "KN" | "TN" | "NT" | "ZZ") || pre == "QQ" {
            hits.push(Hit {
                det: Det::D5Id,
                start: m.start(),
                end: m.end(),
                checksum_ok: true,
            });
        }
    }
    for m in r.iban.find_iter(text) {
        let s = m.as_str();
        let mut chars: Vec<(usize, char)> = Vec::new();
        for (i, c) in s.char_indices() {
            if c != ' ' {
                chars.push((i, c));
            }
        }
        let compact: String = chars.iter().map(|(_, c)| c.to_ascii_uppercase()).collect();
        if let Some(l) = compact.get(..2).and_then(iban_len) {
            if compact.get(..l).is_some_and(iban_ok) {
                let end_off = chars.get(l - 1).map_or(s.len(), |(i, c)| i + c.len_utf8());
                hits.push(Hit {
                    det: Det::D5Id,
                    start: m.start(),
                    end: m.start() + end_off,
                    checksum_ok: true,
                });
            }
        }
    }
    for m in r.email.find_iter(text) {
        hits.push(Hit {
            det: Det::D5Email,
            start: m.start(),
            end: m.end(),
            checksum_ok: false,
        });
    }
    for m in r.e164.find_iter(text) {
        let n = m.as_str().bytes().filter(u8::is_ascii_digit).count();
        if (7..=15).contains(&n) {
            hits.push(Hit {
                det: Det::D5Phone,
                start: m.start(),
                end: m.end(),
                checksum_ok: false,
            });
        }
    }
    for m in r.nanp.find_iter(text) {
        hits.push(Hit {
            det: Det::D5Phone,
            start: m.start(),
            end: m.end(),
            checksum_ok: false,
        });
    }
    for m in r.dob.find_iter(text) {
        hits.push(Hit {
            det: Det::D5Dob,
            start: m.start(),
            end: m.end(),
            checksum_ok: false,
        });
    }
    // D6
    if matches!(kind, ViewKind::Raw | ViewKind::Folded) {
        for m in r.ent.find_iter(text) {
            if entropy(m.as_str()) >= 4.0 {
                hits.push(Hit {
                    det: Det::D6,
                    start: m.start(),
                    end: m.end(),
                    checksum_ok: false,
                });
            }
        }
    }
    dedupe(hits)
}

/// Detectors that also run on a stripped view: D4, D7, D8.
fn run_stripped_rest(text: &str, cfg: &DetectCfg, r: &Rx, hits: &mut Vec<Hit>) {
    // D4
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_digit()) {
            // walk forward collecting digits (single space or dash separators allowed)
            let mut digits: Vec<u8> = Vec::new();
            let mut j = i;
            let mut ends: Vec<(usize, usize)> = Vec::new(); // (digit count, end byte)
            while j < b.len() && digits.len() < 19 {
                if b[j].is_ascii_digit() {
                    digits.push(b[j]);
                    ends.push((digits.len(), j + 1));
                    j += 1;
                } else if (b[j] == b' ' || b[j] == b'-')
                    && j + 1 < b.len()
                    && b[j + 1].is_ascii_digit()
                {
                    j += 1;
                } else {
                    break;
                }
            }
            for (n, end) in ends.iter().rev() {
                if *n < 13 {
                    break;
                }
                let next_digit = b.get(*end).is_some_and(u8::is_ascii_digit);
                if !next_digit {
                    let d: Vec<u8> = b[i..*end]
                        .iter()
                        .copied()
                        .filter(u8::is_ascii_digit)
                        .collect();
                    if d.len() == *n && card_issuer(&d) && luhn(&d) {
                        hits.push(Hit {
                            det: Det::D4,
                            start: i,
                            end: *end,
                            checksum_ok: true,
                        });
                        i = *end;
                        break;
                    }
                }
            }
            // skip the whole digit run
            while i < b.len()
                && (b[i].is_ascii_digit()
                    || ((b[i] == b' ' || b[i] == b'-')
                        && b.get(i + 1).is_some_and(u8::is_ascii_digit)))
            {
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    // D7
    let lower = text.to_lowercase();
    for t in &cfg.terms {
        let mut firsts: Vec<(usize, usize)> = Vec::new();
        let mut found = 0;
        for w in &t.words {
            let needle = if text_is_stripped(&lower, text) {
                strip_needle(w)
            } else {
                norm_words(w)
            };
            if needle.is_empty() {
                continue;
            }
            let pos = if text_is_stripped(&lower, text) {
                (needle.len() >= 8)
                    .then(|| lower.find(&needle))
                    .flatten()
                    .map(|p| (p, p + needle.len()))
            } else {
                let pat: Vec<String> = needle.split(' ').map(regex::escape).collect();
                let b = if t.whole_word { r"\b" } else { "" };
                Regex::new(&format!(r"(?i){b}{}{b}", pat.join(r"[\s_-]+")))
                    .ok()
                    .and_then(|re| re.find(text).map(|m| (m.start(), m.end())))
            };
            if let Some(p) = pos {
                found += 1;
                firsts.push(p);
            }
        }
        let need = if t.all {
            t.words.iter().filter(|w| !norm_words(w).is_empty()).count()
        } else {
            1
        };
        if found >= need.max(1) && !firsts.is_empty() {
            let s = firsts.iter().map(|p| p.0).min().unwrap_or(0);
            let e = firsts.iter().map(|p| p.1).max().unwrap_or(s);
            hits.push(Hit {
                det: Det::D7,
                start: s,
                end: e,
                checksum_ok: false,
            });
        }
    }
    // D8
    for m in cfg.markers.iter() {
        let needle = norm_words(m);
        if needle.is_empty() {
            continue;
        }
        let pos = if text_is_stripped(&lower, text) {
            let n = strip_needle(m);
            (n.len() >= 8)
                .then(|| lower.find(&n))
                .flatten()
                .map(|p| (p, p + n.len()))
        } else {
            let pat: Vec<String> = needle.split(' ').map(regex::escape).collect();
            Regex::new(&format!(r"(?i)\b{}\b", pat.join(r"\s+")))
                .ok()
                .and_then(|re| re.find(text).map(|x| (x.start(), x.end())))
        };
        if let Some((s, e)) = pos {
            hits.push(Hit {
                det: Det::D8,
                start: s,
                end: e,
                checksum_ok: false,
            });
        }
    }
    if !cfg.marker_key.is_empty() {
        for c in r.mark.captures_iter(text) {
            if let (Some(all), Some(a), Some(bb)) = (c.get(0), c.get(1), c.get(2)) {
                let mut h = Sha256::new();
                h.update(&cfg.marker_key);
                h.update(a.as_str().to_lowercase().as_bytes());
                if hex::encode(h.finalize())[..8].eq_ignore_ascii_case(bb.as_str()) {
                    hits.push(Hit {
                        det: Det::D8,
                        start: all.start(),
                        end: all.end(),
                        checksum_ok: true,
                    });
                }
            }
        }
    }
}

/// A stripped view contains no whitespace and no separators; that is how the scanner knows to match by substring.
fn text_is_stripped(lower: &str, text: &str) -> bool {
    lower == text
        && !text.chars().any(|c| {
            c.is_whitespace() || matches!(c, '-' | '_' | '.' | ':' | ',' | ';' | '/' | '\\' | '|')
        })
        && !text.is_empty()
}
fn strip_needle(w: &str) -> String {
    crate::views::strip(w).text
}

fn dedupe(mut v: Vec<Hit>) -> Vec<Hit> {
    v.sort_by_key(|h| (h.det, h.start, h.end));
    v.dedup_by(|a, b| a.det == b.det && a.start == b.start && a.end == b.end);
    v
}
