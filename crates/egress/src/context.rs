//! EG1f context detector (a stage record (not published)): finds a KEY CONTEXT (a name that means a secret) followed by the act of assigning a value, in many syntaxes, whatever the value looks like.
//! It works on bytes and only ever cuts at ASCII characters, so a multibyte character is never split. Heuristic, and it says so: it finds assignments to secret-looking names, not secrets.

/// One finding: the byte range of the value that follows a secret key context, and what kind of context it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Start byte of the value.
    pub start: usize,
    /// End byte (exclusive) of the value.
    pub end: usize,
    /// The kind of context (a closed word).
    pub kind: &'static str,
}

/// What the detector saw in one text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Analysis {
    /// Values assigned to a secret key context that are NOT references or placeholders.
    pub secrets: Vec<Hit>,
    /// Assignments to a secret key context whose value IS a reference or a placeholder (kept so the guard's heuristic blocks on harmless assignments can be reviewed).
    pub references: Vec<Hit>,
}

/// The secret words, letters only (separators between letters are matched loosely).
const WORDS: [&str; 14] = [
    "secret",
    "password",
    "passwd",
    "passphrase",
    "token",
    "apikey",
    "accesskey",
    "credential",
    "privatekey",
    "signingkey",
    "bearer",
    "authorization",
    "identifiedby",
    "converttosecurestring",
];
/// Words allowed after the secret word inside the same identifier (`api_key_value`, `secrets`); anything else (`secretary`, `password_policy`) is not a key context.
const TAIL_OK: [&str; 14] = [
    "keys", "key", "value", "val", "string", "str", "text", "plain", "var", "env", "new", "old",
    "current", "s",
];
const MAX_VALUE: usize = 4096;

fn is_sep(c: u8) -> bool {
    matches!(c, b'-' | b'_' | b'.' | b'/' | b':' | b' ')
}

/// Match `word` at `i` allowing up to two separator characters between its letters; returns (end, used_a_space).
fn loose(b: &[u8], i: usize, word: &str) -> Option<(usize, bool)> {
    let w = word.as_bytes();
    let (mut p, mut spaced) = (i, false);
    for (k, &ch) in w.iter().enumerate() {
        if p >= b.len() || !b[p].eq_ignore_ascii_case(&ch) {
            return None;
        }
        p += 1;
        if k + 1 < w.len() {
            let mut s = 0;
            while s < 3 && p < b.len() && is_sep(b[p]) {
                spaced |= b[p] == b' ';
                p += 1;
                s += 1;
            }
        }
    }
    Some((p, spaced))
}

/// The rest of the identifier after the secret word must be empty or made of allowed words (matched loosely, so a chopped `ke-y` counts); anything else (`secretary`, `password_policy`) is not a key context.
/// Returns the position after the accepted tail.
fn tail(b: &[u8], mut p: usize) -> Option<usize> {
    loop {
        let mut q = p;
        let mut seps = 0;
        let mut ident_sep = false;
        while q < b.len()
            && seps < 3
            && (matches!(b[q], b'_' | b'-' | b'.' | b'/' | b' ')
                || (b[q] == b':' && b.get(q + 1).is_some_and(u8::is_ascii_alphabetic)))
        {
            ident_sep |= !matches!(b[q], b' ' | b':');
            q += 1;
            seps += 1;
        }
        let mut matched = None;
        if q < b.len() && b[q].is_ascii_digit() && (seps == 0 || ident_sep) {
            let mut e = q;
            while e < b.len() && b[e].is_ascii_digit() {
                e += 1;
            }
            matched = Some(e);
        } else {
            for w in TAIL_OK {
                if w == "s" && seps > 0 {
                    continue;
                }
                if let Some((e, _)) = loose(b, q, w) {
                    matched = Some(e);
                    break;
                }
            }
        }
        match matched {
            Some(e) => p = e,
            None => {
                // a separator of the identifier kind followed by another word means the identifier goes on (`password_policy`); letters right after the word too (`secretary`)
                if (ident_sep && q < b.len() && b[q].is_ascii_alphanumeric())
                    || (seps == 0 && q < b.len() && b[q].is_ascii_alphabetic())
                {
                    return None;
                }
                return Some(p);
            }
        }
    }
}

fn line_start(b: &[u8], i: usize) -> usize {
    b[..i]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(0, |p| p + 1)
}

fn is_reference_word(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    matches!(
        l.as_str(),
        "null"
            | "none"
            | "nil"
            | "undefined"
            | "true"
            | "false"
            | "todo"
            | "tbd"
            | "redacted"
            | "empty"
            | "unset"
            | "changeme"
            | "password"
            | "secret"
            | "token"
    )
}

const PLACEHOLDER_WORDS: [&str; 20] = [
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
];

/// A placeholder: after removing placeholder words, separators and brackets nothing of four or more characters is left (digits are NOT removed: `changeme1234` is not a placeholder).
fn placeholder(v: &str) -> bool {
    let mut s = v.to_ascii_lowercase();
    for w in PLACEHOLDER_WORDS {
        s = s.replace(w, "");
    }
    let rest: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    rest.len() < 4
}

fn mask(v: &str) -> bool {
    !v.is_empty()
        && v.chars()
            .all(|c| matches!(c, '*' | 'x' | 'X' | '.' | '-' | '_' | '#' | '•'))
}

/// A reference or template: a variable, a read from the environment, a call, an index, a template.
fn reference(v: &str) -> bool {
    let b = v.as_bytes();
    if b.is_empty() {
        return true;
    }
    if (b[0] == b'$' && is_variable(v))
        || v.starts_with("%(")
        || v.starts_with("%{")
        || v.starts_with("{{")
        || v.starts_with("<%")
        || b[0] == b'<'
        || b[0] == b'['
    {
        return true;
    }
    // Verb-Noun cmdlet: Read-Host, Get-Secret
    if let Some(dash) = v.find('-') {
        let (a, c) = (&v[..dash], &v[dash + 1..]);
        if !a.is_empty()
            && !c.is_empty()
            && a.as_bytes()[0].is_ascii_uppercase()
            && c.as_bytes()[0].is_ascii_uppercase()
            && a.bytes().all(|x| x.is_ascii_alphabetic())
            && c.bytes().all(|x| x.is_ascii_alphabetic())
        {
            return true;
        }
    }
    // call or index: an identifier chain followed by ( or [
    let chain_end = v.bytes().position(|c| {
        !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'>' | b'-' | b'\\'))
    });
    if let Some(e) = chain_end {
        if e > 0 && matches!(b[e], b'(' | b'[') {
            return true;
        }
    }
    mask(v) || is_reference_word(v) || placeholder(v)
}

/// A shell, PowerShell or PHP variable expression: `$name`, `${name}`, `$(cmd)`, `$env:NAME`, `$_ENV['X']`, `$config.Key`, `$args[0]`, `$this->secret`. A `$` followed by symbols (`$w~A%^k`) is not a variable.
fn is_variable(v: &str) -> bool {
    let b = v.as_bytes();
    if b.len() < 2 || b[0] != b'$' {
        return false;
    }
    if b[1] == b'{' || b[1] == b'(' {
        return true;
    }
    if !(b[1].is_ascii_alphabetic() || b[1] == b'_') {
        return false;
    }
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            c if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'\\') => i += 1,
            b'-' if b.get(i + 1) == Some(&b'>') => i += 2,
            b'(' => return true,
            b'[' => match b[i..].iter().position(|&c| c == b']') {
                Some(n) => i += n + 1,
                None => return false,
            },
            _ => return false,
        }
    }
    true
}

fn identifier_like(v: &str) -> bool {
    let b = v.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.'))
}
fn looks_like_secret(v: &str) -> bool {
    v.bytes().any(|c| c.is_ascii_digit())
        && v.bytes().any(|c| c.is_ascii_uppercase())
        && v.bytes().any(|c| c.is_ascii_lowercase())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    /// `key=value` with no space before the `=`, a YAML-style `key: value` at the start of a line, a header, a flag: an unquoted value is a literal.
    Config,
    /// `key = value` with space before the operator: an unquoted identifier-like value is a variable.
    Code,
    /// `Some key: value` inside prose: the value must look like a secret.
    Prose,
}

/// Read a value starting at `p`; returns (start, end, quoted).
fn value_at(b: &[u8], p: usize, xml: bool) -> Option<(usize, usize, bool)> {
    if p >= b.len() {
        return None;
    }
    let q = b[p];
    if matches!(q, b'"' | b'\'' | b'`') {
        let start = p + 1;
        let mut e = start;
        while e < b.len() && b[e] != q && b[e] != b'\n' && e - start < MAX_VALUE {
            if b[e] == b'\\' && e + 1 < b.len() {
                e += 1;
            }
            e += 1;
        }
        return Some((start, e.min(b.len()), true));
    }
    if q == b'{' && b.get(p + 1) == Some(&b'{')
        || q == b'$' && b.get(p + 1) == Some(&b'{')
        || q == b'<' && !xml
        || q == b'['
        || q == b'%' && b.get(p + 1) == Some(&b'(')
    {
        let close = match q {
            b'<' => b'>',
            b'[' => b']',
            b'%' => b')',
            _ => b'}',
        };
        let mut e = p + 1;
        while e < b.len() && b[e] != close && b[e] != b'\n' && e - p < MAX_VALUE {
            e += 1;
        }
        let e = (e + 1).min(b.len());
        return Some((p, e, false));
    }
    let mut e = p;
    while e < b.len() && e - p < MAX_VALUE {
        let c = b[e];
        // an index such as $args[0] or ENV['X'] stays inside the value
        if !xml && c == b'[' {
            if let Some(n) = b[e..(e + 256).min(b.len())]
                .iter()
                .position(|&x| x == b']' || x == b'\n')
            {
                if b[e + n] == b']' {
                    e += n + 1;
                    continue;
                }
            }
        }
        let after_dash = e > p && b[e - 1] == b'-';
        let stop = if xml {
            c == b'<' || c == b'\n'
        } else {
            c.is_ascii_whitespace()
                || matches!(c, b',' | b';' | b')' | b'}' | b']' | b'"' | b'\'')
                || (c == b'>' && !after_dash)
        };
        if stop {
            break;
        }
        e += 1;
    }
    // a call such as getenv('X'): the value is the part before the first quote, which the reference test recognises by its trailing parenthesis
    if e == p {
        return None;
    }
    Some((p, e, false))
}

fn text_of(b: &[u8], s: usize, e: usize) -> &str {
    // s and e are always ASCII boundaries or the end of the text, so this slice is valid UTF-8
    std::str::from_utf8(&b[s..e]).unwrap_or("")
}

/// Analyse one text.
pub fn analyze(text: &str) -> Analysis {
    let b = text.as_bytes();
    let mut out = Analysis::default();
    let mut i = 0;
    while i < b.len() {
        let prev_ok = i == 0
            || !b[i - 1].is_ascii_alphabetic()
            || (b[i - 1].is_ascii_lowercase() && b[i].is_ascii_uppercase());
        if !(b[i].is_ascii_alphabetic() && prev_ok) {
            i += 1;
            continue;
        }
        let mut advanced = false;
        for w in WORDS {
            let Some((e, spaced_key)) = loose(b, i, w) else {
                continue;
            };
            let Some(q) = tail(b, e) else { continue };
            if let Some((hit_start, hit_end, is_ref)) = assignment(b, i, q, w, spaced_key) {
                let hit = Hit {
                    start: hit_start,
                    end: hit_end,
                    kind: "key_context",
                };
                if is_ref {
                    out.references.push(hit);
                } else {
                    out.secrets.push(hit);
                }
                i = hit_end.max(i + 1);
                advanced = true;
            }
            break;
        }
        if !advanced {
            i += 1;
        }
    }
    out
}

/// The start of the identifier that holds the key word (leading dashes of a flag included).
fn ident_start(b: &[u8], key_start: usize) -> usize {
    let mut p = key_start;
    while p > 0 && (b[p - 1].is_ascii_alphanumeric() || matches!(b[p - 1], b'_' | b'-')) {
        p -= 1;
    }
    p
}

/// Is the value a reference, a template or a placeholder (so NOT a secret)? `quoted` says whether it was inside quotes.
fn is_reference(v: &str, quoted: bool, style: Style) -> bool {
    let t = v.trim();
    // a `$` followed only by letters and digits, long and mixed, is a token that happens to start with a dollar sign, not a variable
    if t.len() >= 12
        && t.starts_with('$')
        && t[1..].bytes().all(|c| c.is_ascii_alphanumeric())
        && looks_like_secret(&t[1..])
    {
        return false;
    }
    // a parenthesised expression is a call or a grouping, unless what is inside the parentheses is a quoted literal
    if t.starts_with('(') && !t.trim_start_matches('(').starts_with(['"', '\'']) {
        return true;
    }
    if t.is_empty()
        || t.starts_with("{{")
        || t.starts_with("${")
        || t.starts_with("%(")
        || t.starts_with("<%")
        || (t.starts_with('<') && t.ends_with('>'))
        || (t.starts_with('[') && t.ends_with(']'))
    {
        return true;
    }
    // a YAML tag (`!secret client_secret`) is a reference; a bare authorization scheme (`"Bearer " + token`) is a fragment of a built string
    let scheme_only = matches!(
        t.to_ascii_lowercase().as_str(),
        "bearer" | "token" | "basic" | "apikey" | "digest"
    );
    let yaml_tag = t.len() > 2 && t.starts_with('!') && t.as_bytes()[1].is_ascii_alphabetic();
    if scheme_only || yaml_tag || t.starts_with("ref+") || mask(t) || is_reference_word(t) {
        return true;
    }
    if quoted {
        // a quoted value is a literal unless it is a placeholder with nothing secret-like left
        return placeholder(t) && !looks_like_secret(t);
    }
    if reference(t) {
        return true;
    }
    match style {
        Style::Config => false,
        Style::Code => identifier_like(t) && !looks_like_secret(t) && t.len() < 40,
        Style::Prose => {
            !(t.bytes()
                .any(|c| c.is_ascii_digit() || !c.is_ascii_alphanumeric())
                || t.len() >= 12)
        }
    }
}

/// After a key context ending at `q` (the key word starts at `key_start`), find the assigned value. Returns (value start, value end, is_reference).
fn assignment(
    b: &[u8],
    key_start: usize,
    q: usize,
    word: &str,
    spaced_key: bool,
) -> Option<(usize, usize, bool)> {
    let istart = ident_start(b, key_start);
    let ls = line_start(b, key_start);
    // XML element: <password>value</password>
    if q < b.len() && b[q] == b'>' {
        if istart > ls && b[istart - 1] == b'<' {
            let (s, e, _) = value_at(b, q + 1, true)?;
            let v = text_of(b, s, e);
            if v.len() < 6 {
                return None;
            }
            return Some((s, e, is_reference(v, false, Style::Config)));
        }
        return None;
    }
    // a key that sits just inside an opening quote ("X-Api-Key: value" inside a quoted header): the value runs to the closing quote
    let quote_open = if istart > ls && matches!(b[istart - 1], b'"' | b'\'') {
        Some(b[istart - 1])
    } else {
        None
    };
    let mut r = q;
    while r < b.len() && matches!(b[r], b'\'' | b'"' | b']' | b')' | b'`') {
        r += 1;
    }
    let mut p = r;
    while p < b.len() && (b[p] == b' ' || b[p] == b'\t') {
        p += 1;
    }
    let space_before_op = p > r;
    // a path-like or namespaced key (`vault/kv/token`, `db.password`) counts as one key token
    let mut kstart = istart;
    while kstart > ls
        && (b[kstart - 1].is_ascii_alphanumeric()
            || matches!(b[kstart - 1], b'_' | b'-' | b'.' | b'/' | b':'))
    {
        kstart -= 1;
    }
    let at_line_start = b[ls..kstart].iter().all(|&c| {
        matches!(
            c,
            b' ' | b'\t' | b'"' | b'\'' | b'{' | b',' | b'<' | b'/' | b'$'
        )
    });
    let dash_flag =
        b.get(istart) == Some(&b'-') && (istart == ls || b[istart - 1].is_ascii_whitespace());
    let mut p = p;
    let mut c = *b.get(p)?;
    if c == b'{' {
        // Terraform: variable "password" { default = "v" }
        let eol = b[p..]
            .iter()
            .position(|&x| x == b'\n')
            .map_or(b.len(), |n| p + n);
        let d = b[p..eol]
            .windows(7)
            .position(|w| w.eq_ignore_ascii_case(b"default"))?;
        p += d + 7;
        while p < b.len() && (b[p] == b' ' || b[p] == b'\t') {
            p += 1;
        }
        c = *b.get(p)?;
    }
    let (op_end, style) = if c == b'=' && b.get(p + 1) == Some(&b'>') {
        (p + 2, Style::Config)
    } else if c == b'=' && b.get(p + 1) != Some(&b'=') {
        (
            p + 1,
            if space_before_op || b.get(p + 1) == Some(&b' ') {
                Style::Code
            } else {
                Style::Config
            },
        )
    } else if c == b':' && b.get(p + 1) == Some(&b'=') {
        (p + 2, Style::Code)
    } else if c == b':' && b.get(p + 1) != Some(&b':') && b.get(p + 1) != Some(&b'/') {
        (
            p + 1,
            if spaced_key || !(at_line_start || quote_open.is_some() || r > q) {
                Style::Prose
            } else {
                Style::Config
            },
        )
    } else if c == b'-' && b.get(p + 1) == Some(&b'>') {
        (p + 2, Style::Code)
    } else {
        // no operator: a flag (`--password VALUE`), SQL (`PASSWORD 'v'`, `IDENTIFIED BY 'v'`), PowerShell (`ConvertTo-SecureString "v"`) or a scheme (`Bearer VALUE`)
        let sql_quote = space_before_op
            && matches!(b.get(p), Some(b'\'') | Some(b'"'))
            && matches!(word, "password" | "passwd" | "secret" | "passphrase");
        let keyword_value =
            space_before_op && matches!(word, "identifiedby" | "converttosecurestring" | "bearer");
        let flag = space_before_op && dash_flag;
        if !(sql_quote || keyword_value || flag) {
            return None;
        }
        let (s, e, quoted) = value_at(b, p, false)?;
        let v = text_of(b, s, e);
        if v.len() < 6 {
            return None;
        }
        if !quoted
            && !flag
            && !matches!(word, "identifiedby" | "converttosecurestring")
            && !(looks_like_secret(v)
                || v.bytes().any(|c| !c.is_ascii_alphanumeric() && c != b'_')
                || v.len() >= 16)
        {
            return None;
        }
        return Some((s, e, is_reference(v, quoted, Style::Config)));
    };
    let mut vp = op_end;
    while vp < b.len() && (b[vp] == b' ' || b[vp] == b'\t') {
        vp += 1;
    }
    // Authorization: Token VALUE  /  Authorization: Bearer VALUE: skip the scheme word
    if word == "authorization" {
        for scheme in ["bearer", "token", "apikey", "basic", "key"] {
            if let Some((e, _)) = loose(b, vp, scheme) {
                if e < b.len() && b[e] == b' ' {
                    vp = e + 1;
                    break;
                }
            }
        }
    }
    let first = *b.get(vp)?;
    let (s, e, quoted) = if matches!(first, b'"' | b'\'' | b'`') {
        value_at(b, vp, false)?
    } else if let Some(q) = quote_open {
        // inside an opening quote: to the closing quote of the same kind
        let mut e = vp;
        while e < b.len() && b[e] != q && b[e] != b'\n' && e - vp < MAX_VALUE {
            e += 1;
        }
        (vp, e, false)
    } else if style == Style::Config
        && (c == b':' || at_line_start)
        && !matches!(first, b'$' | b'{' | b'<' | b'[' | b'%' | b'(')
    {
        // a YAML or header value and a properties or env value run to the end of the line
        let mut e = vp;
        while e < b.len() && b[e] != b'\n' && e - vp < MAX_VALUE {
            e += 1;
        }
        while e > vp && b[e - 1].is_ascii_whitespace() {
            e -= 1;
        }
        (vp, e, false)
    } else {
        value_at(b, vp, false)?
    };
    let v = text_of(b, s, e);
    if v.len() < 6 {
        return None;
    }
    // a back-quoted value is a command substitution: a reference
    let backtick = quoted && s > 0 && b[s - 1] == b'`';
    Some((s, e, backtick || is_reference(v, quoted, style)))
}

/// The secret findings of one text.
pub fn scan(text: &str) -> Vec<Hit> {
    analyze(text).secrets
}
