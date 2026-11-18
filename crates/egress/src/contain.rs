//! EG1f containment layer (a stage record (not published)): an outbound payload may carry only TYPED fields; free text only through a declared free-text field.

/// What a field may hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// One of a closed list of codes.
    Code(Vec<String>),
    /// A lowercase hex hash of exactly 64 characters.
    Hash,
    /// An id: 1 to `max` characters from letters, digits, `_` and `-`.
    Id {
        /// Longest id.
        max: usize,
    },
    /// A whole number within the range.
    Int {
        /// Smallest value.
        min: i64,
        /// Largest value.
        max: i64,
    },
    /// A boolean.
    Bool,
    /// Free text of at most `max` characters: the ONLY kind that goes on to the guard.
    FreeText {
        /// Longest text.
        max: usize,
    },
}

/// The fields a payload may carry.
#[derive(Debug, Clone, Default)]
pub struct Schema {
    /// Field name and kind; every other name is refused.
    pub fields: Vec<(String, Kind)>,
}

/// Why a payload was refused (never carries the payload, a field name or a value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not UTF-8 or not JSON.
    NotJson,
    /// A duplicated key.
    DuplicateKey,
    /// The top level is not an object.
    NotObject,
    /// A field the schema does not declare.
    UnknownField,
    /// A value of the wrong type for its field.
    WrongType,
    /// A value outside the closed list or range, or not of the required shape.
    OutOfRange,
    /// A text or id longer than allowed.
    TooLong,
    /// A nested object or array (never declared).
    Nested,
    /// The payload is larger than the limit.
    TooLarge,
}

/// What passed: the free-text values, to be checked by the guard.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contained {
    /// (field name, text) for every free-text field present.
    pub free_text: Vec<(String, String)>,
}

/// The largest payload `check` reads (bytes).
pub const MAX_PAYLOAD_BYTES: usize = 65_536;

struct Pairs(Vec<(String, serde_json::Value)>);
struct PairsVisitor;
impl<'de> serde::de::Visitor<'de> for PairsVisitor {
    type Value = Pairs;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON object")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<Pairs, A::Error> {
        let mut v = Vec::new();
        while let Some((k, val)) = m.next_entry::<String, serde_json::Value>()? {
            v.push((k, val));
        }
        Ok(Pairs(v))
    }
}
impl<'de> serde::Deserialize<'de> for Pairs {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(PairsVisitor)
    }
}

fn is_nested(v: &serde_json::Value) -> bool {
    v.is_object() || v.is_array()
}

fn text_of(v: &serde_json::Value) -> Result<&str, Refusal> {
    if is_nested(v) {
        return Err(Refusal::Nested);
    }
    v.as_str().ok_or(Refusal::WrongType)
}

fn check_field(kind: &Kind, v: &serde_json::Value) -> Result<Option<String>, Refusal> {
    match kind {
        Kind::Code(list) => {
            let t = text_of(v)?;
            if list.iter().any(|c| c == t) {
                Ok(None)
            } else {
                Err(Refusal::OutOfRange)
            }
        }
        Kind::Hash => {
            let t = text_of(v)?;
            if t.len() == 64 && t.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                Ok(None)
            } else {
                Err(Refusal::OutOfRange)
            }
        }
        Kind::Id { max } => {
            let t = text_of(v)?;
            if t.chars().count() > *max {
                return Err(Refusal::TooLong);
            }
            if t.is_empty()
                || !t
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            {
                return Err(Refusal::OutOfRange);
            }
            Ok(None)
        }
        Kind::Int { min, max } => {
            if is_nested(v) {
                return Err(Refusal::Nested);
            }
            let n = v.as_i64().ok_or(Refusal::WrongType)?;
            if n < *min || n > *max {
                Err(Refusal::OutOfRange)
            } else {
                Ok(None)
            }
        }
        Kind::Bool => {
            if is_nested(v) {
                return Err(Refusal::Nested);
            }
            if v.is_boolean() {
                Ok(None)
            } else {
                Err(Refusal::WrongType)
            }
        }
        Kind::FreeText { max } => {
            let t = text_of(v)?;
            if t.chars().count() > *max {
                return Err(Refusal::TooLong);
            }
            Ok(Some(t.to_string()))
        }
    }
}

/// Check a payload against a schema. The refusal never carries the payload, a field name or a value.
pub fn check(schema: &Schema, payload: &[u8]) -> Result<Contained, Refusal> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Refusal::TooLarge);
    }
    let text = std::str::from_utf8(payload).map_err(|_| Refusal::NotJson)?;
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| Refusal::NotJson)?;
    if !value.is_object() {
        return Err(Refusal::NotObject);
    }
    let Pairs(pairs) = serde_json::from_str::<Pairs>(text).map_err(|_| Refusal::NotJson)?;
    let mut seen = std::collections::BTreeSet::new();
    if pairs.iter().any(|(k, _)| !seen.insert(k.as_str())) {
        return Err(Refusal::DuplicateKey);
    }
    let mut out = Contained::default();
    for (name, v) in &pairs {
        let (_, kind) = schema
            .fields
            .iter()
            .find(|(n, _)| n == name)
            .ok_or(Refusal::UnknownField)?;
        if let Some(t) = check_field(kind, v)? {
            out.free_text.push((name.clone(), t));
        }
    }
    Ok(out)
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::NotJson => "not_json",
            Refusal::DuplicateKey => "duplicate_key",
            Refusal::NotObject => "not_object",
            Refusal::UnknownField => "unknown_field",
            Refusal::WrongType => "wrong_type",
            Refusal::OutOfRange => "out_of_range",
            Refusal::TooLong => "too_long",
            Refusal::Nested => "nested",
            Refusal::TooLarge => "too_large",
        })
    }
}
