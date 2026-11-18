//! The strict reader and the canonical writer. Canonical JSON here is RFC 8785-style: UTF-8, no whitespace, object keys sorted by UTF-16 code
//! unit, integers only (u64). The reader accepts ONLY compact input made of printable ASCII (no Unicode, no escapes except `\"` and `\\`),
//! refuses duplicate keys, leading zeros, signs, fractions and exponents, and is bounded in size, depth and node count. Callers then compare the
//! bytes they were given with `write(parse(bytes))`, so the bytes that were signed are exactly the bytes that are read.

/// Largest input accepted (bytes).
pub const MAX_BYTES: usize = 256 * 1024;
/// Deepest nesting of arrays and objects.
pub const MAX_DEPTH: usize = 8;
/// Most values (of any kind) in one document.
pub const MAX_NODES: usize = 4096;

/// A JSON value of the restricted kind tokens use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// An unsigned integer.
    Num(u64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, as written (the reader keeps input order; the writer sorts).
    Object(Vec<(String, Json)>),
}

/// Why the reader refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonError {
    /// No bytes.
    Empty,
    /// More than [`MAX_BYTES`].
    TooLarge,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// More than [`MAX_NODES`] values.
    TooMany,
    /// Not JSON of the accepted shape.
    Syntax,
    /// An object holds the same key twice.
    DuplicateKey,
    /// A number that is not a plain u64.
    BadNumber,
    /// A string with a byte outside printable ASCII or an escape other than `\"` and `\\`.
    BadString,
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
    nodes: usize,
}

/// Read compact canonical-subset JSON.
pub fn parse(b: &[u8]) -> Result<Json, CanonError> {
    if b.is_empty() {
        return Err(CanonError::Empty);
    }
    if b.len() > MAX_BYTES {
        return Err(CanonError::TooLarge);
    }
    let mut p = P { b, i: 0, nodes: 0 };
    let v = p.value(0)?;
    if p.i != b.len() {
        return Err(CanonError::Syntax);
    }
    Ok(v)
}

impl P<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn next(&mut self) -> Result<u8, CanonError> {
        let c = self.peek().ok_or(CanonError::Syntax)?;
        self.i += 1;
        Ok(c)
    }
    fn expect(&mut self, c: u8) -> Result<(), CanonError> {
        if self.next()? == c {
            Ok(())
        } else {
            Err(CanonError::Syntax)
        }
    }
    fn literal(&mut self, word: &[u8]) -> Result<(), CanonError> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(())
        } else {
            Err(CanonError::Syntax)
        }
    }
    fn value(&mut self, depth: usize) -> Result<Json, CanonError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(CanonError::TooMany);
        }
        match self.peek().ok_or(CanonError::Syntax)? {
            b'{' => {
                if depth >= MAX_DEPTH {
                    return Err(CanonError::TooDeep);
                }
                self.i += 1;
                let mut items: Vec<(String, Json)> = Vec::new();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Json::Object(items));
                }
                loop {
                    let k = self.string()?;
                    self.expect(b':')?;
                    let v = self.value(depth + 1)?;
                    if items.iter().any(|(kk, _)| *kk == k) {
                        return Err(CanonError::DuplicateKey);
                    }
                    items.push((k, v));
                    match self.next()? {
                        b',' => continue,
                        b'}' => break,
                        _ => return Err(CanonError::Syntax),
                    }
                }
                Ok(Json::Object(items))
            }
            b'[' => {
                if depth >= MAX_DEPTH {
                    return Err(CanonError::TooDeep);
                }
                self.i += 1;
                let mut items = Vec::new();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Json::Array(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    match self.next()? {
                        b',' => continue,
                        b']' => break,
                        _ => return Err(CanonError::Syntax),
                    }
                }
                Ok(Json::Array(items))
            }
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => self.literal(b"true").map(|()| Json::Bool(true)),
            b'f' => self.literal(b"false").map(|()| Json::Bool(false)),
            b'n' => self.literal(b"null").map(|()| Json::Null),
            b'0'..=b'9' => self.number(),
            b'-' | b'+' | b'.' => Err(CanonError::BadNumber),
            _ => Err(CanonError::Syntax),
        }
    }
    fn number(&mut self) -> Result<Json, CanonError> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        let digits = &self.b[start..self.i];
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(CanonError::BadNumber);
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(CanonError::BadNumber);
        }
        let text = std::str::from_utf8(digits).map_err(|_| CanonError::BadNumber)?;
        text.parse::<u64>()
            .map(Json::Num)
            .map_err(|_| CanonError::BadNumber)
    }
    fn string(&mut self) -> Result<String, CanonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.next()?;
            match c {
                b'"' => return Ok(out),
                b'\\' => match self.next()? {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    _ => return Err(CanonError::BadString),
                },
                0x20..=0x7e => out.push(char::from(c)),
                _ => return Err(CanonError::BadString),
            }
        }
    }
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_into(out: &mut Vec<u8>, j: &Json) {
    match j {
        Json::Null => out.extend_from_slice(b"null"),
        Json::Bool(true) => out.extend_from_slice(b"true"),
        Json::Bool(false) => out.extend_from_slice(b"false"),
        Json::Num(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Json::Str(s) => write_str(out, s),
        Json::Array(a) => {
            out.push(b'[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_into(out, v);
            }
            out.push(b']');
        }
        Json::Object(o) => {
            let mut sorted: Vec<&(String, Json)> = o.iter().collect();
            // RFC 8785: keys sorted by UTF-16 code units
            sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push(b'{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_str(out, k);
                out.push(b':');
                write_into(out, v);
            }
            out.push(b'}');
        }
    }
}

/// The canonical bytes of a value.
pub fn write(j: &Json) -> Vec<u8> {
    let mut out = Vec::new();
    write_into(&mut out, j);
    out
}

impl Json {
    /// The value of `key` when this is an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    /// True when this is an object whose keys are exactly `keys` (no more, no fewer).
    pub fn has_exactly(&self, keys: &[&str]) -> bool {
        match self {
            Json::Object(o) => {
                o.len() == keys.len() && keys.iter().all(|k| o.iter().any(|(kk, _)| kk == k))
            }
            _ => false,
        }
    }
    /// True when this is an object whose keys are all among `keys`.
    pub fn has_only(&self, keys: &[&str]) -> bool {
        match self {
            Json::Object(o) => o.iter().all(|(k, _)| keys.contains(&k.as_str())),
            _ => false,
        }
    }
    /// The string when this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    /// The integer when this is one.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }
}
