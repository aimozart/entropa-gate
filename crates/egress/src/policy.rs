//! The rule language: a closed, total, hashed policy document. No scripting, no client patterns, no includes, no network fetch. An invalid or
//! unverifiable policy is fail closed (F3).
use crate::detect::{Det, DetectCfg, Term};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::str::FromStr;

/// Access tier of the caller (T0 public, T1 staff, T2 agents, T3 build).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs)]
pub enum Tier {
    T0,
    T1,
    T2,
    T3,
}
impl Tier {
    /// The wire id.
    pub fn as_str(self) -> &'static str {
        ["T0", "T1", "T2", "T3"][self as usize]
    }
}
impl FromStr for Tier {
    type Err = ();
    fn from_str(s: &str) -> Result<Tier, ()> {
        match s {
            "T0" => Ok(Tier::T0),
            "T1" => Ok(Tier::T1),
            "T2" => Ok(Tier::T2),
            "T3" => Ok(Tier::T3),
            _ => Err(()),
        }
    }
}

/// What to do with a match. Ordered by strictness: allow < redact < block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs)]
pub enum Mode {
    AllowWithRecord,
    Redact,
    Block,
}
impl Mode {
    fn parse(s: &str) -> Option<Mode> {
        match s {
            "allow_with_record" => Some(Mode::AllowWithRecord),
            "redact" => Some(Mode::Redact),
            "block" => Some(Mode::Block),
            _ => None,
        }
    }
}

/// Why a policy was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Not valid JSON or not the policy shape.
    Malformed(String),
    /// The signature did not verify.
    Signature,
    /// Valid shape, invalid content.
    Invalid(String),
}

/// Verifies a policy signature over the canonical bytes. EG1 injects this; the real ML-DSA verifier is wired in a later stage (EG3), so EG1
/// proves fail-closed on a bad verdict only, not that policies are signed.
pub trait PolicyVerifier {
    /// True when `signature` is a valid signature over `canonical`.
    fn verify(&self, canonical: &[u8], signature: &str) -> bool;
}

/// A deterministic hash check for tests. It is NOT a signature scheme.
pub struct DevHashVerifier(Vec<u8>);
impl DevHashVerifier {
    /// A verifier with a key.
    pub fn new(key: &[u8]) -> DevHashVerifier {
        DevHashVerifier(key.to_vec())
    }
}
impl PolicyVerifier for DevHashVerifier {
    fn verify(&self, canonical: &[u8], signature: &str) -> bool {
        dev_sig(&self.0, canonical) == signature
    }
}
fn dev_sig(key: &[u8], canonical: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(key);
    h.update(canonical);
    hex::encode(h.finalize())
}
fn canonical_of(v: &Value) -> Vec<u8> {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("signature");
    }
    serde_json::to_vec(&v).unwrap_or_default()
}
/// Add a dev signature to a policy JSON text (tests and tools).
pub fn sign_dev(json_text: &str, key: &[u8]) -> String {
    let mut v: Value = serde_json::from_str(json_text).unwrap_or(Value::Null);
    let sig = dev_sig(key, &canonical_of(&v));
    if let Some(o) = v.as_object_mut() {
        o.insert("signature".into(), Value::String(sig));
    }
    v.to_string()
}

/// The default policy template (EG0 section 3), without a signature.
pub fn template_json(host: &str) -> String {
    let lim = |bytes: u64, depth: u64, fields: u64, att: u64, attb: u64, tail: u64| json!({"bytes":bytes,"depth":depth,"fields":fields,"attachments":att,"attachment_bytes":attb,"tail_bytes":tail});
    let dets = |email: &str| json!({"D1":"block","D2":"block","D3":"block","D4":"block","D5.id":"block","D5.email":email,"D5.phone":email,"D5.dob":"block","D6":"allow_with_record","D7":"block","D8":"block"});
    json!({
        "version":"1","name":"eg1-default","key_id":"dev",
        "destinations":[{"id":"d1","scheme":"https","host":host,"port":443,"allow_tiers":["T1","T2","T3"]}],
        "limits":{"T0":lim(0,0,0,0,0,0),"T1":lim(65536,8,256,0,0,4096),"T2":lim(262144,16,1024,4,1048576,4096),"T3":lim(1048576,32,4096,8,4194304,8192)},
        "detectors":{"T0":dets("block"),"T1":dets("redact"),"T2":dets("redact"),"T3":dets("redact")},
        "tiers":{"T0":{"allow_egress":false},"T1":{"allow_egress":true},"T2":{"allow_egress":true},"T3":{"allow_egress":true}},
        "terms":[],"markers":[],"marker_key":"","examples":[]
    })
    .to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDest {
    id: String,
    scheme: String,
    host: String,
    port: u16,
    allow_tiers: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    bytes: usize,
    depth: usize,
    fields: usize,
    attachments: usize,
    attachment_bytes: usize,
    tail_bytes: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTier {
    allow_egress: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTerm {
    words: Vec<String>,
    whole_word: bool,
    all: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    version: String,
    name: String,
    key_id: String,
    #[serde(default)]
    signature: String,
    destinations: Vec<RawDest>,
    limits: BTreeMap<String, RawLimits>,
    detectors: BTreeMap<String, BTreeMap<String, String>>,
    tiers: BTreeMap<String, RawTier>,
    terms: Vec<RawTerm>,
    markers: Vec<String>,
    marker_key: String,
    examples: Vec<String>,
}

/// A destination on the closed list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Id used in records.
    pub id: String,
    /// `https` or `http`.
    pub scheme: String,
    /// Lower-case ASCII host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Tiers that may use it.
    pub allow_tiers: Vec<Tier>,
}

/// Size and shape limits of a tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Body bytes.
    pub bytes: usize,
    /// JSON depth.
    pub depth: usize,
    /// JSON values.
    pub fields: usize,
    /// Attachments per request.
    pub attachments: usize,
    /// Bytes per attachment.
    pub attachment_bytes: usize,
    /// Conversation tail bytes joined to the scan.
    pub tail_bytes: usize,
}

/// A verified, valid policy.
#[derive(Debug, Clone)]
pub struct Policy {
    hash: String,
    version: String,
    dests: Vec<Destination>,
    limits: BTreeMap<Tier, Limits>,
    modes: BTreeMap<(Tier, Det), Mode>,
    egress: BTreeMap<Tier, bool>,
    cfg: DetectCfg,
}

fn bad<T>(m: &str) -> Result<T, PolicyError> {
    Err(PolicyError::Invalid(m.to_string()))
}
fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !h.starts_with(['.', '-'])
        && !h.ends_with(['.', '-'])
        && !h.contains("..")
        && !h
            .split('.')
            .any(|l| l.is_empty() || l.starts_with("xn--") || l.len() > 63)
        && !h.split('.').all(|l| l.bytes().all(|b| b.is_ascii_digit()))
        && h.contains('.')
}

impl Policy {
    /// Parse, verify the signature, then validate. Any failure is an error; callers must then block (F3).
    pub fn parse(json_text: &str, verifier: &dyn PolicyVerifier) -> Result<Policy, PolicyError> {
        let v: Value =
            serde_json::from_str(json_text).map_err(|e| PolicyError::Malformed(e.to_string()))?;
        let canonical = canonical_of(&v);
        let sig = v.get("signature").and_then(Value::as_str).unwrap_or("");
        if !verifier.verify(&canonical, sig) {
            return Err(PolicyError::Signature);
        }
        let raw: Raw =
            serde_json::from_value(v).map_err(|e| PolicyError::Malformed(e.to_string()))?;
        let _ = (&raw.name, &raw.key_id, &raw.signature);
        if raw.version.is_empty() {
            return bad("empty version");
        }
        let mut dests = Vec::new();
        for d in &raw.destinations {
            if !matches!(d.scheme.as_str(), "https" | "http")
                || !host_ok(&d.host)
                || d.port == 0
                || d.id.is_empty()
            {
                return bad("destination");
            }
            let mut tiers = Vec::new();
            for t in &d.allow_tiers {
                match t.parse::<Tier>() {
                    Ok(Tier::T0) | Err(()) => {
                        return bad("destination tiers (T0 can never have a destination)")
                    }
                    Ok(t) => tiers.push(t),
                }
            }
            dests.push(Destination {
                id: d.id.clone(),
                scheme: d.scheme.clone(),
                host: d.host.clone(),
                port: d.port,
                allow_tiers: tiers,
            });
        }
        let mut limits = BTreeMap::new();
        for (k, l) in &raw.limits {
            let Ok(t) = k.parse::<Tier>() else {
                return bad("limits tier");
            };
            limits.insert(
                t,
                Limits {
                    bytes: l.bytes,
                    depth: l.depth,
                    fields: l.fields,
                    attachments: l.attachments,
                    attachment_bytes: l.attachment_bytes,
                    tail_bytes: l.tail_bytes,
                },
            );
        }
        let mut egress = BTreeMap::new();
        for (k, t) in &raw.tiers {
            let Ok(tier) = k.parse::<Tier>() else {
                return bad("tiers");
            };
            if tier == Tier::T0 && t.allow_egress {
                return bad("T0 has no egress");
            }
            egress.insert(tier, t.allow_egress);
        }
        let mut modes = BTreeMap::new();
        for (k, m) in &raw.detectors {
            let Ok(tier) = k.parse::<Tier>() else {
                return bad("detectors tier");
            };
            for (d, mode) in m {
                let (Some(det), Some(mode)) = (Det::parse(d), Mode::parse(mode)) else {
                    return bad("detector id or mode");
                };
                modes.insert((tier, det), mode);
            }
        }
        for t in [Tier::T0, Tier::T1, Tier::T2, Tier::T3] {
            if !limits.contains_key(&t) || !egress.contains_key(&t) {
                return bad("every tier needs limits and a tier entry");
            }
        }
        let get = |t: Tier, d: Det| modes.get(&(t, d)).copied().unwrap_or(Mode::Block);
        for d in [Det::D1, Det::D2, Det::D3, Det::D4] {
            if get(Tier::T3, d) != Mode::Block {
                return bad("D1 to D4 may not be below block at T3");
            }
        }
        for d in [Det::D1, Det::D2, Det::D3, Det::D4, Det::D5Id] {
            if get(Tier::T3, d) < get(Tier::T1, d) || get(Tier::T2, d) < get(Tier::T1, d) {
                return bad("floor classes may not loosen toward higher tiers");
            }
        }
        let cfg = DetectCfg {
            terms: raw
                .terms
                .iter()
                .map(|t| Term {
                    words: t.words.clone(),
                    whole_word: t.whole_word,
                    all: t.all,
                })
                .collect(),
            markers: raw.markers.clone(),
            marker_key: raw.marker_key.clone().into_bytes(),
            examples: raw.examples.clone(),
        };
        let mut h = Sha256::new();
        h.update(&canonical);
        Ok(Policy {
            hash: hex::encode(h.finalize()),
            version: raw.version,
            dests,
            limits,
            modes,
            egress,
            cfg,
        })
    }

    /// The policy hash (over the canonical bytes without the signature).
    pub fn hash(&self) -> String {
        self.hash.clone()
    }
    /// The policy version.
    pub fn version(&self) -> &str {
        &self.version
    }
    /// The mode of a detector at a tier (default block).
    pub fn mode(&self, tier: Tier, det: Det) -> Mode {
        self.modes.get(&(tier, det)).copied().unwrap_or(Mode::Block)
    }
    /// The limits of a tier.
    pub fn limits(&self, tier: Tier) -> Limits {
        self.limits.get(&tier).copied().unwrap_or(Limits {
            bytes: 0,
            depth: 0,
            fields: 0,
            attachments: 0,
            attachment_bytes: 0,
            tail_bytes: 0,
        })
    }
    /// May this tier send at all?
    pub fn allows_egress(&self, tier: Tier) -> bool {
        tier != Tier::T0 && self.egress.get(&tier).copied().unwrap_or(false)
    }
    /// The detector configuration.
    pub fn detect_cfg(&self) -> &DetectCfg {
        &self.cfg
    }
    /// The closed-list destination an exact URL names for this tier, or `None`.
    pub fn destination(&self, url: &str, tier: Tier) -> Option<&Destination> {
        if tier == Tier::T0 {
            return None;
        }
        let u = parse_url(url)?;
        if u.userinfo {
            return None;
        }
        self.dests.iter().find(|d| {
            d.scheme == u.scheme
                && d.host == u.host
                && d.port == u.port
                && d.allow_tiers.contains(&tier)
        })
    }
}

/// A strictly parsed URL.
pub struct ParsedUrl {
    /// Lower-case scheme.
    pub scheme: String,
    /// Lower-case host.
    pub host: String,
    /// Port (default per scheme).
    pub port: u16,
    /// Userinfo present.
    pub userinfo: bool,
}

/// Strict URL parsing for the destination check: no whitespace or control characters, no backslashes, no IP literals, no punycode, no trailing dot.
pub fn parse_url(url: &str) -> Option<ParsedUrl> {
    if url.is_empty()
        || url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        || !url.is_ascii()
    {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "https" | "http") {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..end];
    let userinfo = auth.contains('@');
    if userinfo {
        return Some(ParsedUrl {
            scheme,
            host: String::new(),
            port: 0,
            userinfo: true,
        });
    }
    let (host, port) = match auth.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (auth, if scheme == "https" { 443 } else { 80 }),
    };
    let host = host.to_ascii_lowercase();
    if !host_ok(&host) {
        return None;
    }
    Some(ParsedUrl {
        scheme,
        host,
        port,
        userinfo: false,
    })
}
