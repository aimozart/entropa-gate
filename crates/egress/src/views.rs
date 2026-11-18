//! The views a detector runs on: folded (look-alikes mapped, invisible characters dropped), stripped (also separators removed and lower-cased),
//! and decoded (bounded decoders, depth 3). Each view keeps a map back to the raw text so a match can be redacted in place.

/// A view of a text with, for each character of the view, the byte range of the raw text it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    /// The view text.
    pub text: String,
    /// For each character of `text`, the raw byte range (start, end).
    pub spans: Vec<(usize, usize)>,
}

/// A decoded candidate: the decoded text, the raw token it came from, and the decoders applied in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The decoded text (lossy UTF-8).
    pub text: String,
    /// The byte range of the raw token it was decoded from.
    pub src: (usize, usize),
    /// Decoder names, outermost first.
    pub chain: Vec<&'static str>,
}

/// Look-alike letter (Cyrillic, Greek) to its ASCII letter, keeping case.
pub fn confusable(c: char) -> Option<char> {
    Some(match c {
        '\u{ff01}'..='\u{ff5e}' => char::from_u32(c as u32 - 0xfee0)?,
        '\u{430}' | '\u{3b1}' => 'a',
        '\u{435}' => 'e',
        '\u{43e}' | '\u{3bf}' => 'o',
        '\u{440}' | '\u{3c1}' => 'p',
        '\u{441}' => 'c',
        '\u{445}' => 'x',
        '\u{443}' => 'y',
        '\u{456}' | '\u{3b9}' => 'i',
        '\u{458}' => 'j',
        '\u{455}' => 's',
        '\u{501}' => 'd',
        '\u{4bb}' => 'h',
        '\u{3bd}' => 'v',
        '\u{3ba}' => 'k',
        '\u{3c5}' => 'u',
        '\u{410}' | '\u{391}' => 'A',
        '\u{412}' | '\u{392}' => 'B',
        '\u{415}' | '\u{395}' => 'E',
        '\u{41a}' | '\u{39a}' => 'K',
        '\u{41c}' | '\u{39c}' => 'M',
        '\u{41d}' | '\u{397}' => 'H',
        '\u{41e}' | '\u{39f}' => 'O',
        '\u{420}' | '\u{3a1}' => 'P',
        '\u{421}' => 'C',
        '\u{422}' | '\u{3a4}' => 'T',
        '\u{425}' | '\u{3a7}' => 'X',
        '\u{406}' | '\u{399}' => 'I',
        '\u{408}' => 'J',
        '\u{405}' => 'S',
        '\u{396}' => 'Z',
        '\u{39d}' => 'N',
        '\u{3a5}' => 'Y',
        _ => return None,
    })
}

fn invisible(c: char) -> bool {
    matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}' | '\u{ad}')
        || (c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
}

/// The folded view: look-alikes mapped to ASCII (case kept), invisible and control characters dropped, newlines and tabs kept as spaces.
pub fn fold(raw: &str) -> View {
    let mut text = String::with_capacity(raw.len());
    let mut spans = Vec::with_capacity(raw.len());
    for (i, c) in raw.char_indices() {
        if invisible(c) {
            continue;
        }
        let end = i + c.len_utf8();
        let c = if matches!(c, '\n' | '\t' | '\r') {
            ' '
        } else {
            confusable(c).unwrap_or(c)
        };
        text.push(c);
        spans.push((i, end));
    }
    View { text, spans }
}

fn separator(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '-' | '_' | '.' | ':' | ',' | ';' | '/' | '\\' | '|' | '\u{a0}'
        )
}

/// The stripped view: folded, separators removed, lower-cased (ASCII).
pub fn strip(raw: &str) -> View {
    let f = fold(raw);
    let mut text = String::with_capacity(f.text.len());
    let mut spans = Vec::with_capacity(f.text.len());
    for (c, s) in f.text.chars().zip(f.spans.iter()) {
        if separator(c) {
            continue;
        }
        text.push(c.to_ascii_lowercase());
        spans.push(*s);
    }
    View { text, spans }
}

/// Characters that end a token for the decoders.
fn delimiter(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ','
        )
}

fn tokens(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in s.char_indices() {
        if delimiter(c) {
            if let Some(a) = start.take() {
                out.push((a, i));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(a) = start {
        out.push((a, s.len()));
    }
    out
}

fn printable(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let ok = b
        .iter()
        .filter(|c| matches!(**c, 0x20..=0x7e | b'\n' | b'\t' | b'\r') || **c >= 0x80)
        .count();
    ok * 10 >= b.len() * 9
}

fn b64_decode(t: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let t = t.trim_end_matches('=');
    if t.len() < 12
        || !t
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
    {
        return None;
    }
    let std = t.replace('-', "+").replace('_', "/");
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(std)
        .ok()
}
fn b32_decode(t: &str) -> Option<Vec<u8>> {
    let t = t.trim_end_matches('=');
    if t.len() < 16
        || !t
            .bytes()
            .all(|b| b.is_ascii_alphabetic() || (b'2'..=b'7').contains(&b))
    {
        return None;
    }
    let (mut bits, mut n, mut out) = (0u32, 0u32, Vec::new());
    for b in t.bytes() {
        let v = match b.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c => c - b'2' + 26,
        } as u32;
        bits = (bits << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push(((bits >> n) & 0xff) as u8);
            bits &= (1 << n) - 1;
        }
    }
    Some(out)
}
fn hex_decode(t: &str) -> Option<Vec<u8>> {
    let t = t.strip_prefix("0x").unwrap_or(t);
    if t.len() < 16 || !t.len().is_multiple_of(2) || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(t).ok()
}
fn percent_decode(t: &str) -> Option<Vec<u8>> {
    let b = t.as_bytes();
    let (mut out, mut i, mut n) = (Vec::with_capacity(b.len()), 0, 0);
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
        {
            out.push(u8::from_str_radix(&t[i + 1..i + 3], 16).ok()?);
            i += 3;
            n += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    (n >= 2).then_some(out)
}
fn escape_decode(t: &str, u: bool) -> Option<Vec<u8>> {
    let (pre, w) = if u { ("\\u", 4) } else { ("\\x", 2) };
    let (mut out, mut rest, mut n) = (String::new(), t, 0);
    while let Some(i) = rest.find(pre) {
        out.push_str(&rest[..i]);
        let hexs = rest.get(i + 2..i + 2 + w)?;
        let cp = u32::from_str_radix(hexs, 16).ok()?;
        out.push(char::from_u32(cp)?);
        rest = &rest[i + 2 + w..];
        n += 1;
    }
    out.push_str(rest);
    (n >= 2).then(|| out.into_bytes())
}
fn entity_decode(t: &str) -> Option<Vec<u8>> {
    let (mut out, mut rest, mut n) = (String::new(), t, 0);
    while let Some(i) = rest.find("&#") {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 2..];
        let end = tail.find(';')?;
        let body = &tail[..end];
        let cp = match body.strip_prefix(['x', 'X']) {
            Some(h) => u32::from_str_radix(h, 16).ok()?,
            None => body.parse().ok()?,
        };
        out.push(char::from_u32(cp)?);
        rest = &tail[end + 1..];
        n += 1;
    }
    out.push_str(rest);
    (n >= 2).then(|| out.into_bytes())
}
fn rot13(t: &str) -> Option<Vec<u8>> {
    if t.chars().count() < 12 || !t.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(
        t.chars()
            .map(|c| match c {
                'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
                'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
                o => o,
            })
            .collect::<String>()
            .into_bytes(),
    )
}
fn reverse(t: &str) -> Option<Vec<u8>> {
    (t.chars().count() >= 12).then(|| t.chars().rev().collect::<String>().into_bytes())
}

type Dec = (&'static str, fn(&str) -> Option<Vec<u8>>);
const STRUCTURAL: &[Dec] = &[
    ("base64", b64_decode),
    ("base32", b32_decode),
    ("hex", hex_decode),
    ("percent", percent_decode),
    ("escape_u", |t| escape_decode(t, true)),
    ("escape_x", |t| escape_decode(t, false)),
    ("entity", entity_decode),
];
const SIMPLE: &[Dec] = &[("rot13", rot13), ("reverse", reverse)];

/// Maximum decoding depth.
pub const MAX_DEPTH: usize = 3;

/// Longest line the leaf candidates are made from (the hyphen removal tries up to six candidates per line).
const LEAF_MAX: usize = 4096;

/// EG1c: candidates made from a whole LEAF rather than one token: the whole text (when it has more than one word) and each line of at least 12
/// characters, rot13'd and reversed (a keyword and its value disguised together land in one decoded text), and each line with a regular
/// hyphen grouping (a hyphen at every g+1-th position, g from 3 to 8, at least two of them) removed. Same expansion budget as the token-wise views.
fn leaf_candidates(raw: &str, budget: &mut usize, out: &mut Vec<Decoded>) {
    let mut leaves: Vec<(usize, usize)> = Vec::new();
    if raw.chars().any(char::is_whitespace) {
        leaves.push((0, raw.len()));
    }
    let mut at = 0;
    for line in raw.split('\n') {
        let end = at + line.len();
        // a single-line text without a space is its own leaf too (the hyphen candidates need it; rot13 and reverse are left to the token-wise views)
        let whole_line = (at, end) == (0, raw.len());
        if line.chars().count() >= 12 && (!whole_line || !raw.chars().any(char::is_whitespace)) {
            leaves.push((at, end));
        }
        at = end + 1;
    }
    for (a, b) in leaves {
        let leaf = &raw[a..b];
        if leaf.len() > LEAF_MAX && (a, b) != (0, raw.len()) {
            continue;
        }
        // a multi-line whole text gets rot13 and reverse only: its lines are leaves of their own and carry the hyphen candidates
        let cands = leaf_expansions(leaf, !((a, b) == (0, raw.len()) && leaf.contains('\n')));
        for (chain, bytes) in cands {
            if !printable(&bytes) {
                continue;
            }
            let text = String::from_utf8_lossy(&bytes).into_owned();
            if text.len() > *budget {
                continue;
            }
            *budget -= text.len();
            out.push(Decoded {
                text,
                src: (a, b),
                chain,
            });
        }
    }
}

/// Longest leaf on which compounds of two operators are tried.
const COMPOUND_MAX: usize = 1024;

/// Most candidates made from one leaf (the work bound of the expansion below).
const LEAF_CANDIDATES_MAX: usize = 24;

/// EG1d: the candidates of one leaf: depth 1 is one operator (rot13, reverse, remove regular hyphens, remove all hyphens), depth 2 is a second operator on a depth-1 result (the compounds of two
/// disguises). A depth-1 candidate carries the chain `[operator]` (as in EG1c); a depth-2 candidate `["compound", last operator]`, so the view kind follows the LAST operator.
pub fn leaf_expansions(leaf: &str, hyphens: bool) -> Vec<(Vec<&'static str>, Vec<u8>)> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(leaf.to_string());
    let mut out: Vec<(Vec<&'static str>, Vec<u8>)> = Vec::new();
    let mut level: Vec<String> = vec![leaf.to_string()];
    // the second operator (compounds of two disguises) is tried on leaves up to 1 KiB only: a long leaf costs a full scan per candidate (a documented limit, EG1d)
    let max_depth = if leaf.len() <= COMPOUND_MAX { 2 } else { 1 };
    for depth in 0..max_depth {
        let mut next: Vec<String> = Vec::new();
        for t in &level {
            for (name, nt) in leaf_ops(t, depth == 0, hyphens) {
                if out.len() >= LEAF_CANDIDATES_MAX {
                    return out;
                }
                if !seen.insert(nt.clone()) {
                    continue;
                }
                let chain = if depth == 0 {
                    vec![name]
                } else {
                    vec!["compound", name]
                };
                out.push((chain, nt.clone().into_bytes()));
                next.push(nt);
            }
        }
        level = next;
    }
    out
}

/// One operator step. rot13 and reverse need a leaf with more than one word at depth 0 (the token-wise views cover a single word).
fn leaf_ops(t: &str, depth0: bool, hyphens: bool) -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> = Vec::new();
    if !depth0 || t.chars().any(char::is_whitespace) {
        for (name, f) in SIMPLE {
            if let Some(bytes) = f(t) {
                v.push((*name, String::from_utf8_lossy(&bytes).into_owned()));
            }
        }
    }
    if t.len() <= LEAF_MAX {
        if let Some(x) = join_split_keywords(t) {
            v.push(("split", x));
        }
    }
    if hyphens && t.len() <= LEAF_MAX && t.contains('-') {
        for g in 3..=8usize {
            if let Some(x) = remove_regular_hyphens(t, g) {
                v.push(("hyphen", x));
            }
        }
        for g in 2..=10usize {
            if let Some(x) = remove_hyphen_window(t, g) {
                v.push(("hyphen", x));
            }
        }
        if t.bytes().filter(|b| *b == b'-').count() >= 3 {
            v.push(("hyphen", t.replace('-', "")));
        }
        if let Some(x) = remove_separators(t) {
            v.push(("hyphen", x));
        }
        if let Some(x) = remove_separators_keep_spaces(t) {
            v.push(("hyphen", x));
        }
    }
    v
}

/// The key words the join looks for (EG1d): a keyword cut by one space or a zero-width character (`Bea rer`, `pa ssword`) is joined back; at most two cuts per keyword.
const SPLIT_KEYWORDS: [&str; 10] = [
    "authorization",
    "bearer",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "client_secret",
    "access_key",
];
/// Join a key word cut by one or two spaces or zero-width characters back together (`pa ssword` to `password`); `None` when nothing was joined.
pub fn join_split_keywords(t: &str) -> Option<String> {
    let c: Vec<char> = t.chars().collect();
    let n = c.len();
    let cut = |ch: char| matches!(ch, ' ' | '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{00ad}');
    let mut out = String::with_capacity(t.len());
    let (mut i, mut changed) = (0, false);
    while i < n {
        let mut hit: Option<(usize, &str)> = None;
        for kw in SPLIT_KEYWORDS {
            let k = kw.as_bytes();
            // cheap first-letter test before any work (this runs at every position of every candidate)
            if !c[i].is_ascii() || c[i].to_ascii_lowercase() as u8 != k[0] {
                continue;
            }
            let (mut j, mut m, mut cuts) = (i, 0, 0);
            while m < k.len() {
                if j < n && c[j].is_ascii() && c[j].to_ascii_lowercase() as u8 == k[m] {
                    j += 1;
                    m += 1;
                } else if m > 0
                    && cuts < 2
                    && j + 1 < n
                    && cut(c[j])
                    && c[j + 1].is_ascii()
                    && c[j + 1].to_ascii_lowercase() as u8 == k[m]
                {
                    j += 1;
                    cuts += 1;
                } else {
                    break;
                }
            }
            if m == k.len() && cuts > 0 {
                hit = Some((j, kw));
                break;
            }
        }
        if let Some((j, kw)) = hit {
            out.push_str(kw);
            i = j;
            changed = true;
        } else {
            out.push(c[i]);
            i += 1;
        }
    }
    changed.then_some(out)
}

/// EG1e: delete every `-`, `_` and `.` and the spaces that touch a deleted one (a phrase chopped by mixed separators: `Au-tho-riz-ation: Be-ar-er X`, `ap-i_-key=X`, `tok-.en=X`); only
/// when at least three separators are present or two of them touch (`_-`, `-.`). The result is scanned like any other candidate.
pub fn remove_separators(s: &str) -> Option<String> {
    strip_separators(s, true)
}

/// The same without touching the spaces (a real space next to a separator stays: `Bearer-_ BFt` is `Bearer BFt`); keyword joins that need the cut spaces are done by `join_split_keywords` on this result.
pub fn remove_separators_keep_spaces(s: &str) -> Option<String> {
    strip_separators(s, false)
}

fn strip_separators(s: &str, spaces_too: bool) -> Option<String> {
    let c: Vec<char> = s.chars().collect();
    let sep = |ch: char| matches!(ch, '-' | '_' | '.');
    let adjacent = c.windows(2).any(|w| sep(w[0]) && sep(w[1]));
    if c.iter().filter(|ch| sep(**ch)).count() < 3 && !adjacent {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    for (i, ch) in c.iter().enumerate() {
        if sep(*ch) {
            continue;
        }
        if spaces_too
            && *ch == ' '
            && ((i > 0 && sep(c[i - 1])) || c.get(i + 1).is_some_and(|n| sep(*n)))
        {
            continue;
        }
        out.push(*ch);
    }
    Some(out)
}

/// Find the first run (starting anywhere in the line) with a hyphen at three or more regular positions, `g` characters apart, and remove the hyphens of that run.
pub fn remove_hyphen_window(s: &str, g: usize) -> Option<String> {
    let c: Vec<char> = s.chars().collect();
    let n = c.len();
    for start in 0..n {
        let first = start + g;
        let regular = |k: usize| first + k * (g + 1);
        if (0..3).all(|k| regular(k) < n && c[regular(k)] == '-') {
            let mut skip: Vec<usize> = Vec::new();
            let mut k = 0;
            while regular(k) < n && c[regular(k)] == '-' {
                skip.push(regular(k));
                k += 1;
            }
            return Some(
                c.iter()
                    .enumerate()
                    .filter(|(i, _)| !skip.contains(i))
                    .map(|(_, ch)| *ch)
                    .collect(),
            );
        }
    }
    None
}

/// Remove the character at every (g+1)-th position (1-based) if and only if every one of them is a hyphen and there are at least two.
fn remove_regular_hyphens(s: &str, g: usize) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut removed = 0;
    for (i, c) in s.chars().enumerate() {
        if (i + 1) % (g + 1) == 0 {
            if c != '-' {
                return None;
            }
            removed += 1;
        } else {
            out.push(c);
        }
    }
    (removed >= 2).then_some(out)
}

/// The decoded view: every token decoded by every recognised decoder, repeated to depth 3, within an expansion budget of four times the
/// input (plus 1,024 bytes). rot13 and reverse apply at the first level only. A decoded text must be at least 90 percent printable.
pub fn decoded(raw: &str) -> Vec<Decoded> {
    let mut budget = raw.len().saturating_mul(4).saturating_add(1024);
    let mut out: Vec<Decoded> = Vec::new();
    let mut level: Vec<Decoded> = tokens(raw)
        .into_iter()
        .map(|(a, b)| Decoded {
            text: raw[a..b].to_string(),
            src: (a, b),
            chain: vec![],
        })
        .collect();
    leaf_candidates(raw, &mut budget, &mut out);
    for depth in 0..MAX_DEPTH {
        let mut next: Vec<Decoded> = Vec::new();
        for item in &level {
            let toks: Vec<(usize, usize)> = if depth == 0 {
                vec![(0, item.text.len())]
            } else {
                tokens(&item.text)
            };
            for (a, b) in toks {
                let tok = &item.text[a..b];
                let simple: &[Dec] = if depth == 0 { SIMPLE } else { &[] };
                for (name, f) in STRUCTURAL.iter().chain(simple.iter()) {
                    if let Some(bytes) = f(tok) {
                        if !printable(&bytes) {
                            continue;
                        }
                        let text = String::from_utf8_lossy(&bytes).into_owned();
                        if text.len() > budget {
                            continue;
                        }
                        budget -= text.len();
                        let mut chain = item.chain.clone();
                        chain.push(name);
                        let d = Decoded {
                            text,
                            src: item.src,
                            chain,
                        };
                        next.push(d.clone());
                        out.push(d);
                    }
                }
            }
        }
        level = next;
        if level.is_empty() {
            break;
        }
    }
    out
}
