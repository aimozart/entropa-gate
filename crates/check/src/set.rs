//! The sealed set `entropa-sealed-v1`.
use crate::Refusal;

/// One case of a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// Case id.
    pub id: String,
    /// Class name.
    pub class: String,
    /// The input bytes.
    pub input: Vec<u8>,
    /// The expected verdict: `block` or `allow`.
    pub expect: String,
    /// True when an `allow` means an attack was accepted.
    pub attack: bool,
    /// Strings that must never appear in the target's output.
    pub secrets: Vec<String>,
    /// The per-case time limit in milliseconds.
    pub timeout_ms: u64,
}

/// A parsed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Set {
    /// The cases in file order.
    pub cases: Vec<Case>,
}

const MAX_FILE: usize = 32 * 1024 * 1024;
const MAX_INPUT: usize = 1024 * 1024;
const MAX_CASES: usize = 5000;
const CASE_FIELDS: [&str; 7] = [
    "id",
    "class",
    "input",
    "expect",
    "attack",
    "secrets",
    "timeout_ms",
];

/// Parse and validate a set (strict: see the schema page). Refusals never echo the file's content.
pub fn parse(bytes: &[u8]) -> Result<Set, Refusal> {
    if bytes.len() > MAX_FILE {
        return Err(Refusal::new("the file is larger than 32 MiB"));
    }
    let v = crate::strict(bytes)?;
    let top = v
        .as_object()
        .ok_or_else(|| Refusal::new("the file is not an object"))?;
    if top.keys().any(|k| k != "schema" && k != "cases") {
        return Err(Refusal::new("the file has a field outside the schema"));
    }
    if top.get("schema").and_then(|s| s.as_str()) != Some("entropa-sealed-v1") {
        return Err(Refusal::new("the schema is not entropa-sealed-v1"));
    }
    let arr = top
        .get("cases")
        .and_then(|c| c.as_array())
        .ok_or_else(|| Refusal::new("the file has no cases list"))?;
    if arr.len() > MAX_CASES {
        return Err(Refusal::new("more than 5,000 cases"));
    }
    let mut cases = Vec::with_capacity(arr.len());
    let mut seen = std::collections::HashSet::new();
    for (i, c) in arr.iter().enumerate() {
        let bad = |m: &str| Refusal(format!("case #{i}: {m}"));
        let o = c.as_object().ok_or_else(|| bad("not an object"))?;
        if o.keys().any(|k| !CASE_FIELDS.contains(&k.as_str())) {
            return Err(bad("a field outside the schema"));
        }
        let id = o
            .get("id")
            .and_then(|x| x.as_str())
            .filter(|s| crate::name_ok(s))
            .ok_or_else(|| bad("the id is missing or outside the pattern"))?;
        let class = o
            .get("class")
            .and_then(|x| x.as_str())
            .filter(|s| crate::name_ok(s))
            .ok_or_else(|| bad("the class is missing or outside the pattern"))?;
        if !seen.insert(id.to_string()) {
            return Err(bad("a duplicate id"));
        }
        let expect = o
            .get("expect")
            .and_then(|x| x.as_str())
            .filter(|s| *s == "block" || *s == "allow")
            .ok_or_else(|| bad("expect must be block or allow"))?;
        let inp = o
            .get("input")
            .and_then(|x| x.as_object())
            .ok_or_else(|| bad("the input is missing"))?;
        let input = match (inp.get("text"), inp.get("hex"), inp.len()) {
            (Some(t), None, 1) => t
                .as_str()
                .ok_or_else(|| bad("input.text is not a string"))?
                .as_bytes()
                .to_vec(),
            (None, Some(h), 1) => {
                hex::decode(h.as_str().ok_or_else(|| bad("input.hex is not a string"))?)
                    .map_err(|_| bad("input.hex is not hex"))?
            }
            _ => return Err(bad("the input needs exactly one of text or hex")),
        };
        if input.len() > MAX_INPUT {
            return Err(bad("the input is larger than 1 MiB"));
        }
        let attack = match o.get("attack") {
            None => false,
            Some(a) => a
                .as_bool()
                .ok_or_else(|| bad("attack must be true or false"))?,
        };
        let secrets = match o.get("secrets") {
            None => Vec::new(),
            Some(s) => {
                let l = s.as_array().ok_or_else(|| bad("secrets must be a list"))?;
                if l.len() > 100 {
                    return Err(bad("more than 100 secrets"));
                }
                l.iter()
                    .map(|x| {
                        x.as_str()
                            .filter(|t| !t.is_empty() && t.len() <= 4096)
                            .map(String::from)
                            .ok_or_else(|| {
                                bad("a secret is not a non-empty string of at most 4096 bytes")
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
        };
        let timeout_ms = match o.get("timeout_ms") {
            None => 5000,
            Some(t) => t
                .as_u64()
                .filter(|t| (1..=60_000).contains(t))
                .ok_or_else(|| bad("timeout_ms must be 1 to 60000"))?,
        };
        cases.push(Case {
            id: id.to_string(),
            class: class.to_string(),
            input,
            expect: expect.to_string(),
            attack,
            secrets,
            timeout_ms,
        });
    }
    Ok(Set { cases })
}
