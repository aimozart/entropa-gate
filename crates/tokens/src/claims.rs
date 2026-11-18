//! The claims of a token, their closed character sets, and the narrowing law (a child never exceeds its parent).

use crate::canon::Json;
use crate::Deny;

/// Access tier. Ordered: a higher tier may do more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Public.
    T0,
    /// Staff.
    T1,
    /// Agents.
    T2,
    /// Build and train.
    T3,
}

impl Tier {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::T0 => "t0",
            Tier::T1 => "t1",
            Tier::T2 => "t2",
            Tier::T3 => "t3",
        }
    }
    /// Parse the wire name.
    pub fn parse(s: &str) -> Option<Tier> {
        match s {
            "t0" => Some(Tier::T0),
            "t1" => Some(Tier::T1),
            "t2" => Some(Tier::T2),
            "t3" => Some(Tier::T3),
            _ => None,
        }
    }
}

/// What a token grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// 32 lowercase hex characters.
    pub token_id: String,
    /// Pseudonym, `[a-z0-9._-]{1,64}`.
    pub subject: String,
    /// Tier.
    pub tier: Tier,
    /// Corpus hashes (64 lowercase hex), strictly increasing, at most 32.
    pub corpora: Vec<String>,
    /// Tool or action names, `[a-z0-9._:-]{1,64}`, strictly increasing, at most 64.
    pub actions: Vec<String>,
    /// Spend cap in micro-USD.
    pub spend_cap: u64,
    /// Calls per minute.
    pub rate_cap: u64,
    /// Unix seconds; the token is not valid before this (less the verifier's skew).
    pub not_before: u64,
    /// Unix seconds; the token is expired when `now >= expiry`.
    pub expiry: u64,
    /// Node the token is for, `[a-z0-9._-]{1,64}`.
    pub audience: String,
    /// Token id of the parent, or none.
    pub parent: Option<String>,
}

/// Most corpora in one token.
pub const MAX_CORPORA: usize = 32;
/// Most actions in one token.
pub const MAX_ACTIONS: usize = 64;

pub(crate) fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}
fn is_name(s: &str, extra: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(&c))
}
fn strictly_increasing(v: &[String]) -> bool {
    v.windows(2).all(|w| w[0] < w[1])
}

impl Claims {
    /// Check every field against its closed set and the limits.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !is_hex(&self.token_id, 32) {
            return Err("token_id");
        }
        if !is_name(&self.subject, b"._-") {
            return Err("subject");
        }
        if !is_name(&self.audience, b"._-") {
            return Err("audience");
        }
        if self.corpora.len() > MAX_CORPORA
            || !self.corpora.iter().all(|c| is_hex(c, 64))
            || !strictly_increasing(&self.corpora)
        {
            return Err("corpora");
        }
        if self.actions.len() > MAX_ACTIONS
            || !self.actions.iter().all(|a| is_name(a, b"._:-"))
            || !strictly_increasing(&self.actions)
        {
            return Err("actions");
        }
        if self.not_before >= self.expiry {
            return Err("validity window");
        }
        if let Some(p) = &self.parent {
            if !is_hex(p, 32) || *p == self.token_id {
                return Err("parent");
            }
        }
        Ok(())
    }

    /// The claims as a JSON object.
    pub fn to_json(&self) -> Json {
        let strs = |v: &[String]| Json::Array(v.iter().cloned().map(Json::Str).collect());
        Json::Object(vec![
            ("token_id".into(), Json::Str(self.token_id.clone())),
            ("subject".into(), Json::Str(self.subject.clone())),
            ("tier".into(), Json::Str(self.tier.as_str().into())),
            ("corpora".into(), strs(&self.corpora)),
            ("actions".into(), strs(&self.actions)),
            ("spend_cap".into(), Json::Num(self.spend_cap)),
            ("rate_cap".into(), Json::Num(self.rate_cap)),
            ("not_before".into(), Json::Num(self.not_before)),
            ("expiry".into(), Json::Num(self.expiry)),
            ("audience".into(), Json::Str(self.audience.clone())),
            (
                "parent".into(),
                self.parent.clone().map_or(Json::Null, Json::Str),
            ),
        ])
    }

    /// Read claims from a JSON object (exactly the eleven keys) and validate them.
    pub fn from_json(j: &Json) -> Result<Claims, Deny> {
        const KEYS: [&str; 11] = [
            "token_id",
            "subject",
            "tier",
            "corpora",
            "actions",
            "spend_cap",
            "rate_cap",
            "not_before",
            "expiry",
            "audience",
            "parent",
        ];
        if !j.has_exactly(&KEYS) {
            return Err(Deny::Malformed);
        }
        let s = |k: &str| {
            j.get(k)
                .and_then(Json::as_str)
                .map(String::from)
                .ok_or(Deny::Malformed)
        };
        let n = |k: &str| j.get(k).and_then(Json::as_u64).ok_or(Deny::Malformed);
        let list = |k: &str| -> Result<Vec<String>, Deny> {
            match j.get(k) {
                Some(Json::Array(a)) => a
                    .iter()
                    .map(|v| v.as_str().map(String::from).ok_or(Deny::Malformed))
                    .collect(),
                _ => Err(Deny::Malformed),
            }
        };
        let parent = match j.get("parent") {
            Some(Json::Null) => None,
            Some(Json::Str(p)) => Some(p.clone()),
            _ => return Err(Deny::Malformed),
        };
        let c = Claims {
            token_id: s("token_id")?,
            subject: s("subject")?,
            tier: Tier::parse(&s("tier")?).ok_or(Deny::Malformed)?,
            corpora: list("corpora")?,
            actions: list("actions")?,
            spend_cap: n("spend_cap")?,
            rate_cap: n("rate_cap")?,
            not_before: n("not_before")?,
            expiry: n("expiry")?,
            audience: s("audience")?,
            parent,
        };
        c.validate().map_err(|_| Deny::Malformed)?;
        Ok(c)
    }
}

fn subset(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|c| parent.contains(c))
}

/// The narrowing law: a child never exceeds its parent on any field. Returns the first field that does.
pub fn check_narrower(parent: &Claims, child: &Claims) -> Result<(), &'static str> {
    if child.tier > parent.tier {
        return Err("tier");
    }
    if !subset(&child.corpora, &parent.corpora) {
        return Err("corpora");
    }
    if !subset(&child.actions, &parent.actions) {
        return Err("actions");
    }
    if child.spend_cap > parent.spend_cap {
        return Err("spend_cap");
    }
    if child.rate_cap > parent.rate_cap {
        return Err("rate_cap");
    }
    if child.not_before < parent.not_before {
        return Err("not_before");
    }
    if child.expiry > parent.expiry {
        return Err("expiry");
    }
    if child.audience != parent.audience {
        return Err("audience");
    }
    if child.subject != parent.subject {
        return Err("subject");
    }
    Ok(())
}
