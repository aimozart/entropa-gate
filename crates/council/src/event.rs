//! Closed-code events: strict decoder, canonical bytes, domain-separated digest, signing and verification.

use crate::canon::canonical;
use crate::schema::{fields_of, is_session_bound, Kind, CHECKS, EVIDENCE_KINDS, RECOMMENDATIONS};
use crate::CouncilError;
use entropa_core::CheckpointSigner;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Longest signature accepted, in hex characters (an ML-DSA-65 signature is 6,618).
const MAX_SIG_HEX: usize = 16_384;

/// What validation returns: the event type, its fields without the signature, and the signature (if one is required).
type Validated = (String, BTreeMap<String, Value>, Option<String>);

/// A decoded council event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    ty: String,
    fields: BTreeMap<String, Value>,
    sig: String,
}

impl Event {
    /// The event type, for example `finding.submitted`.
    pub fn event_type(&self) -> &str {
        &self.ty
    }
    /// The session this event belongs to, if it is session-bound.
    pub fn session_id(&self) -> Option<&str> {
        self.str_field("session_id")
    }
    /// The signed fields as canonical JSON (keys sorted, no whitespace, no `sig`).
    pub fn canonical_json(&self) -> String {
        canonical(&self.value())
    }
    pub(crate) fn value(&self) -> Value {
        Value::Object(
            self.fields
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Map<String, Value>>(),
        )
    }
    pub(crate) fn str_field(&self, k: &str) -> Option<&str> {
        self.fields.get(k).and_then(Value::as_str)
    }
    pub(crate) fn u64_field(&self, k: &str) -> Option<u64> {
        self.fields.get(k).and_then(Value::as_u64)
    }
    pub(crate) fn bool_field(&self, k: &str) -> Option<bool> {
        self.fields.get(k).and_then(Value::as_bool)
    }
    pub(crate) fn array_field(&self, k: &str) -> &[Value] {
        self.fields
            .get(k)
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }
}

fn bad(what: &str) -> CouncilError {
    CouncilError::Invalid(what.to_string())
}

pub(crate) fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

pub(crate) fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// An algorithm label: 1 to 32 characters of `A-Za-z0-9._-`.
fn is_alg(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_sig(s: &str) -> bool {
    !s.is_empty()
        && s.len().is_multiple_of(2)
        && s.len() <= MAX_SIG_HEX
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn u64_of(v: &Value) -> Option<u64> {
    if v.is_u64() {
        v.as_u64()
    } else {
        None
    }
}

/// True if any string anywhere in `v` contains a canary token prefix (P0: a canary can never enter an event).
fn holds_canary(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains(entropa_synthetic::CANARY_PREFIX),
        Value::Array(a) => a.iter().any(holds_canary),
        Value::Object(m) => m.values().any(holds_canary),
        _ => false,
    }
}

fn check_kind(name: &str, kind: Kind, v: &Value) -> Result<(), CouncilError> {
    let ok = match kind {
        Kind::Hex64 => v.as_str().is_some_and(|s| is_hex(s, 64)),
        Kind::Hex64OrNull => v.is_null() || v.as_str().is_some_and(|s| is_hex(s, 64)),
        Kind::Token => v.as_str().is_some_and(is_token),
        Kind::TokenOrNull => v.is_null() || v.as_str().is_some_and(is_token),
        Kind::Enum(list) => v.as_str().is_some_and(|s| list.contains(&s)),
        Kind::U64 => u64_of(v).is_some(),
        Kind::Permille => u64_of(v).is_some_and(|n| n <= 1000),
        Kind::Bool => v.is_boolean(),
        Kind::Evidence => v
            .as_array()
            .is_some_and(|a| a.len() <= 8 && a.iter().all(evidence_item)),
        Kind::TokenList5 => token_list(v, 5),
        Kind::TokenList64 => token_list(v, 64),
        Kind::Items => v
            .as_array()
            .is_some_and(|a| a.len() <= 12 && a.iter().all(packet_item)),
    };
    if ok {
        Ok(())
    } else {
        Err(CouncilError::Invalid(format!("field {name} is not valid")))
    }
}

fn token_list(v: &Value, max: usize) -> bool {
    v.as_array()
        .is_some_and(|a| a.len() <= max && a.iter().all(|x| x.as_str().is_some_and(is_token)))
}

fn has_exactly(m: &Map<String, Value>, keys: &[&str]) -> bool {
    m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k))
}

fn evidence_item(v: &Value) -> bool {
    v.as_object().is_some_and(|m| {
        has_exactly(m, &["kind", "ref"])
            && m.get("kind")
                .and_then(Value::as_str)
                .is_some_and(|k| EVIDENCE_KINDS.contains(&k))
            && m.get("ref").and_then(Value::as_str).is_some_and(is_token)
    })
}

fn packet_item(v: &Value) -> bool {
    v.as_object().is_some_and(|m| {
        has_exactly(m, &["finding_id", "check", "recommendation"])
            && m.get("finding_id")
                .and_then(Value::as_str)
                .is_some_and(is_token)
            && m.get("check")
                .and_then(Value::as_str)
                .is_some_and(|c| CHECKS.contains(&c))
            && m.get("recommendation")
                .and_then(Value::as_str)
                .is_some_and(|r| RECOMMENDATIONS.contains(&r))
    })
}

/// Cross-field rules that the per-field kinds cannot express.
fn invariants(ty: &str, f: &BTreeMap<String, Value>) -> Result<(), CouncilError> {
    let n = |k: &str| f.get(k).and_then(Value::as_u64).unwrap_or(0);
    let ok = match ty {
        "session.opened" => n("period_start") < n("period_end") && n("expires") > n("ts"),
        "packet.compiled" => f
            .get("items")
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() as u64 == n("item_count")),
        "proof.recorded" => {
            n("newly_denied") + n("newly_allowed") <= n("n_changed")
                && n("n_changed") <= n("n_replayed")
        }
        "precedent.referenced" => {
            (1..=5).contains(&n("k"))
                && f.get("precedent_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.len() as u64 == n("k"))
        }
        "evaluation.recorded" => n("hindsight_gap_pp") <= 100,
        "carryover.recorded" => f
            .get("carried_ids")
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() as u64 <= n("n_candidates")),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(CouncilError::Invalid(format!(
            "{ty}: fields are inconsistent"
        )))
    }
}

/// Validate an event object. `with_sig` says whether a `sig` is required (decode) or forbidden (sign).
pub(crate) fn validate(v: &Value, with_sig: bool) -> Result<Validated, CouncilError> {
    let obj = v
        .as_object()
        .ok_or_else(|| bad("an event is a JSON object"))?;
    if holds_canary(v) {
        return Err(bad("a canary token can never enter an event"));
    }
    let ty = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("type is missing"))?;
    let specific = fields_of(ty).ok_or_else(|| bad("unknown event type"))?;
    let bound = is_session_bound(ty);
    let mut allowed: Vec<&str> = vec!["v", "type", "actor", "ts", "alg"];
    if bound {
        allowed.push("session_id");
    }
    if with_sig {
        allowed.push("sig");
    }
    allowed.extend(specific.iter().map(|(k, _)| *k));
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(bad("an unknown field is present"));
    }
    if allowed.iter().any(|k| !obj.contains_key(*k)) {
        return Err(bad("a required field is missing"));
    }
    if obj.get("v").and_then(u64_of) != Some(1) {
        return Err(bad("v must be 1"));
    }
    if !obj
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|s| is_hex(s, 16))
    {
        return Err(bad("actor must be a 16-hex key id"));
    }
    if !obj.get("alg").and_then(Value::as_str).is_some_and(is_alg) {
        return Err(bad("alg must be an algorithm label"));
    }
    if obj.get("ts").and_then(u64_of).is_none() {
        return Err(bad("ts must be a non-negative integer"));
    }
    if bound
        && !obj
            .get("session_id")
            .and_then(Value::as_str)
            .is_some_and(|s| is_hex(s, 64))
    {
        return Err(bad("session_id must be 64 hex digits"));
    }
    for (name, kind) in specific {
        if let Some(x) = obj.get(*name) {
            check_kind(name, *kind, x)?;
        }
    }
    let sig = if with_sig {
        let s = obj
            .get("sig")
            .and_then(Value::as_str)
            .filter(|s| is_sig(s))
            .ok_or_else(|| bad("sig must be lower-case hex"))?;
        Some(s.to_string())
    } else {
        None
    };
    let fields: BTreeMap<String, Value> = obj
        .iter()
        .filter(|(k, _)| k.as_str() != "sig")
        .map(|(k, x)| (k.clone(), x.clone()))
        .collect();
    invariants(ty, &fields)?;
    Ok((ty.to_string(), fields, sig))
}

/// Decode a signed payload strictly: unknown fields, wrong types, wrong `v`, upper-case hex, tokens over 64
/// characters, unknown codes, oversize lists, canary tokens and any free-text field are refused. The signature is
/// checked for shape only; use [`verify_event`] to check it.
pub fn decode_event(payload: &str) -> Result<Event, CouncilError> {
    let v: Value = serde_json::from_str(payload).map_err(|_| bad("not valid JSON"))?;
    let (ty, fields, sig) = validate(&v, true)?;
    Ok(Event {
        ty,
        fields,
        sig: sig.unwrap_or_default(),
    })
}

/// Canonical bytes of the event without its signature.
pub fn canonical_bytes(e: &Event) -> Vec<u8> {
    e.canonical_json().into_bytes()
}

/// The signed digest: `BLAKE3("entropa-council-v1" 0x00 || u32be(len) || canonical)`.
pub fn event_digest(canonical: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-council-v1\0");
    h.update(&(canonical.len() as u32).to_be_bytes());
    h.update(canonical);
    *h.finalize().as_bytes()
}

/// Validate an unsigned event (the same JSON without `sig`), sign it, and return the signed payload.
pub fn sign_event(
    signer: &impl CheckpointSigner,
    unsigned_json: &str,
) -> Result<String, CouncilError> {
    let v: Value = serde_json::from_str(unsigned_json).map_err(|_| bad("not valid JSON"))?;
    let (_, fields, _) = validate(&v, false)?;
    if fields.get("alg").and_then(Value::as_str) != Some(signer.algorithm()) {
        return Err(bad("the alg label is not the signer's algorithm"));
    }
    let canon = canonical(&Value::Object(
        fields.iter().map(|(k, x)| (k.clone(), x.clone())).collect(),
    ));
    let sig = signer
        .try_sign_hex(&event_digest(canon.as_bytes()))
        .map_err(|e| CouncilError::Sign(e.to_string()))?;
    let mut signed: Map<String, Value> = fields.into_iter().collect();
    signed.insert("sig".into(), Value::String(sig));
    Ok(canonical(&Value::Object(signed)))
}

/// Verifies signatures of one algorithm, named by its label.
pub trait SignatureVerifier {
    /// The algorithm label, for example `ML-DSA-65`.
    fn algorithm(&self) -> &'static str;
    /// True if `sig_hex` is a valid signature of `msg` under `pubkey_hex`.
    fn verify(&self, pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> bool;
}

struct MlDsa65;
impl SignatureVerifier for MlDsa65 {
    fn algorithm(&self) -> &'static str {
        "ML-DSA-65"
    }
    fn verify(&self, pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
        entropa_core::verify_hex(pubkey_hex, msg, sig_hex)
    }
}

/// The algorithms a verifier is configured to accept; the default knows ML-DSA-65 only.
pub struct Registry {
    verifiers: BTreeMap<&'static str, Box<dyn SignatureVerifier>>,
}

impl Default for Registry {
    fn default() -> Self {
        Registry::empty().with(Box::new(MlDsa65))
    }
}

impl Registry {
    /// A registry that knows no algorithm.
    pub fn empty() -> Registry {
        Registry {
            verifiers: BTreeMap::new(),
        }
    }
    /// This registry plus one more verifier (replacing one with the same label).
    pub fn with(mut self, v: Box<dyn SignatureVerifier>) -> Registry {
        self.verifiers.insert(v.algorithm(), v);
        self
    }
    /// The labels this registry accepts, sorted.
    pub fn algorithms(&self) -> Vec<&'static str> {
        self.verifiers.keys().copied().collect()
    }
}

/// Decode a payload and verify its signature under `pubkey_hex` with the default registry (ML-DSA-65 only).
pub fn verify_event(payload: &str, pubkey_hex: &str) -> Result<Event, CouncilError> {
    verify_event_with(payload, pubkey_hex, &Registry::default())
}

/// Decode a payload and verify its signature through `registry`, dispatching on the signed `alg` label.
pub fn verify_event_with(
    payload: &str,
    pubkey_hex: &str,
    registry: &Registry,
) -> Result<Event, CouncilError> {
    let e = decode_event(payload)?;
    let label = e.str_field("alg").unwrap_or_default();
    let verifier = registry
        .verifiers
        .get(label)
        .ok_or_else(|| CouncilError::Verify("unsupported signature algorithm".into()))?;
    let digest = event_digest(&canonical_bytes(&e));
    if verifier.verify(pubkey_hex, &digest, &e.sig) {
        Ok(e)
    } else {
        Err(CouncilError::Verify(
            "event signature does not verify".into(),
        ))
    }
}
