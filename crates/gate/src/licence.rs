//! The offline licence file (S1 slice C): canonical JSON signed with ML-DSA-65, checked against an embedded key with a stated clock tolerance.
//! No network, no system clock inside the library (the caller passes `now`), fail closed on every doubt. The issuer key stays with the owner; the
//! ability to issue exists only behind the `issue` feature (tests and the issuer tool), never in the client binary.
use entropa_tokens::canon::{parse, write, Json};
use entropa_tokens::{digest, key_id_of};

/// Verify a hex ML-DSA-65 signature over a digest under a hex public key (length and alphabet checked by the tokens crate).
fn sig_ok(pubkey_hex: &str, d: &[u8; 32], sig_hex: &str) -> bool {
    sig_hex.len() == entropa_tokens::SIG_HEX_LEN
        && sig_hex
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        && key_id_of(pubkey_hex).is_some()
        && entropa_core::verify_hex(pubkey_hex, d, sig_hex)
}

/// The product name a licence must carry.
pub const PRODUCT: &str = "entropa-gate";
/// The largest licence accepted (bytes).
pub const MAX_LICENCE_BYTES: usize = 16 * 1024;
/// Default clock tolerance on both ends of the validity window (24 hours).
pub const DEFAULT_TOLERANCE_SECS: u64 = 24 * 60 * 60;

/// The claims of a licence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// Must equal [`PRODUCT`].
    pub product: String,
    /// Pseudonymous customer id (8 to 64 of a-z, 0-9, hyphen).
    pub customer_id: String,
    /// Entitlements (1 to 16 distinct names of a-z, 0-9, underscore, hyphen).
    pub entitlements: Vec<String>,
    /// Start of validity (unix seconds).
    pub not_before: u64,
    /// End of validity (unix seconds).
    pub expiry: u64,
    /// The build this licence was issued for (1 to 64 of letters, digits, dot, underscore, hyphen).
    pub build_id: String,
    /// The per-copy mark (16 to 64 of a-z, 0-9).
    pub mark: String,
}

/// What a check needs besides the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The current time (unix seconds), passed in by the caller.
    pub now: u64,
    /// Tolerance on both ends of the window, in seconds.
    pub tolerance_secs: u64,
    /// An entitlement that must be present, if any.
    pub require: Option<String>,
}

/// Why a licence was refused (closed list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deny {
    /// Not the accepted JSON shape (or not UTF-8 printable ASCII, or a duplicated key).
    Malformed,
    /// Valid JSON but not in canonical form.
    NotCanonical,
    /// Over [`MAX_LICENCE_BYTES`].
    TooLarge,
    /// Version, algorithm or key id field is wrong.
    BadHeader,
    /// The key id is not the trusted key.
    UnknownKey,
    /// The signature does not verify.
    BadSignature,
    /// A claim is outside its allowed form.
    BadField,
    /// The product is not [`PRODUCT`].
    WrongProduct,
    /// Past expiry plus tolerance.
    Expired,
    /// Before not_before minus tolerance.
    NotYetValid,
    /// The required entitlement is missing.
    MissingEntitlement,
}

impl Deny {
    /// The closed code.
    pub fn as_str(self) -> &'static str {
        match self {
            Deny::Malformed => "malformed",
            Deny::NotCanonical => "not_canonical",
            Deny::TooLarge => "too_large",
            Deny::BadHeader => "bad_header",
            Deny::UnknownKey => "unknown_key",
            Deny::BadSignature => "bad_signature",
            Deny::BadField => "bad_field",
            Deny::WrongProduct => "wrong_product",
            Deny::Expired => "expired",
            Deny::NotYetValid => "not_yet_valid",
            Deny::MissingEntitlement => "missing_entitlement",
        }
    }
}

const KEYS: [&str; 11] = [
    "alg",
    "build_id",
    "customer_id",
    "entitlements",
    "expiry",
    "key_id",
    "mark",
    "not_before",
    "product",
    "sig",
    "v",
];
/// The longest validity window a licence may carry (five years, in seconds).
pub const MAX_WINDOW_SECS: u64 = 5 * 365 * 24 * 60 * 60;

fn chars_ok(s: &str, min: usize, max: usize, ok: impl Fn(char) -> bool) -> bool {
    (min..=max).contains(&s.len()) && s.chars().all(ok)
}
fn text<'a>(j: &'a Json, k: &str) -> Result<&'a str, Deny> {
    j.get(k).and_then(Json::as_str).ok_or(Deny::Malformed)
}
fn num(j: &Json, k: &str) -> Result<u64, Deny> {
    j.get(k).and_then(Json::as_u64).ok_or(Deny::Malformed)
}

/// Check a licence against the trusted public key (hex) under a policy. Order: size, strict parse, canonical bytes, header, key, signature, claim
/// forms, product, time window, required entitlement. Every failure is a closed code; nothing is read from the system.
pub fn check(bytes: &[u8], trusted_pubkey_hex: &str, policy: &Policy) -> Result<Claims, Deny> {
    if bytes.len() > MAX_LICENCE_BYTES {
        return Err(Deny::TooLarge);
    }
    let j = parse(bytes).map_err(|_| Deny::Malformed)?;
    if write(&j) != bytes {
        return Err(Deny::NotCanonical);
    }
    if !j.has_exactly(&KEYS) {
        return Err(Deny::Malformed);
    }
    if num(&j, "v")? != 1 || text(&j, "alg")? != "ML-DSA-65" {
        return Err(Deny::BadHeader);
    }
    let kid = text(&j, "key_id")?;
    if !chars_ok(kid, 16, 16, |c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(Deny::BadHeader);
    }
    if key_id_of(trusted_pubkey_hex).as_deref() != Some(kid) {
        return Err(Deny::UnknownKey);
    }
    let sig = text(&j, "sig")?;
    let Json::Object(fields) = &j else {
        return Err(Deny::Malformed);
    };
    let msg = Json::Object(fields.iter().filter(|(k, _)| k != "sig").cloned().collect());
    if !sig_ok(trusted_pubkey_hex, &digest("licence", &write(&msg)), sig) {
        return Err(Deny::BadSignature);
    }
    // the signature holds: the fields are the issuer's, but their form is still checked (an issuer mistake must not become a licence)
    let product = text(&j, "product")?;
    let customer_id = text(&j, "customer_id")?;
    let build_id = text(&j, "build_id")?;
    let mark = text(&j, "mark")?;
    let Some(Json::Array(ents)) = j.get("entitlements") else {
        return Err(Deny::Malformed);
    };
    let mut entitlements = Vec::new();
    for e in ents {
        let Json::Str(e) = e else {
            return Err(Deny::BadField);
        };
        entitlements.push(e.clone());
    }
    let (not_before, expiry) = (num(&j, "not_before")?, num(&j, "expiry")?);
    let forms = chars_ok(product, 1, 64, |c| c.is_ascii_graphic())
        && chars_ok(
            customer_id,
            8,
            64,
            |c| matches!(c, 'a'..='z' | '0'..='9' | '-'),
        )
        && chars_ok(build_id, 1, 64, |c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
        })
        && chars_ok(mark, 16, 64, |c| matches!(c, 'a'..='z' | '0'..='9'))
        && (1..=16).contains(&entitlements.len())
        && entitlements
            .iter()
            .all(|e| chars_ok(e, 1, 32, |c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-')))
        && entitlements
            .iter()
            .enumerate()
            .all(|(i, e)| !entitlements[..i].contains(e))
        && expiry > not_before
        && expiry - not_before <= MAX_WINDOW_SECS;
    if !forms {
        return Err(Deny::BadField);
    }
    if product != PRODUCT {
        return Err(Deny::WrongProduct);
    }
    if policy.now.saturating_add(policy.tolerance_secs) < not_before {
        return Err(Deny::NotYetValid);
    }
    if policy.now > expiry.saturating_add(policy.tolerance_secs) {
        return Err(Deny::Expired);
    }
    if let Some(r) = &policy.require {
        if !entitlements.contains(r) {
            return Err(Deny::MissingEntitlement);
        }
    }
    Ok(Claims {
        product: product.to_string(),
        customer_id: customer_id.to_string(),
        entitlements,
        not_before,
        expiry,
        build_id: build_id.to_string(),
        mark: mark.to_string(),
    })
}
