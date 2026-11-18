//! Issuing a licence (feature `issue`, off in the client binary): the issuer key stays with the owner; this exists for the tests and the issuer tool.
use crate::licence::{Claims, PRODUCT};
use entropa_core::Probe;
use entropa_tokens::canon::{write, Json};
use entropa_tokens::{digest, key_id_of};

/// Sign the claims with the issuer key; returns the canonical licence bytes. Refuses claims that `check` would refuse as malformed in form.
pub fn issue(issuer: &Probe, c: &Claims) -> Option<Vec<u8>> {
    if c.product != PRODUCT {
        return None;
    }
    let kid = key_id_of(&issuer.pubkey_hex())?;
    let s = |v: &str| Json::Str(v.to_string());
    let msg = Json::Object(vec![
        ("alg".into(), s("ML-DSA-65")),
        ("build_id".into(), s(&c.build_id)),
        ("customer_id".into(), s(&c.customer_id)),
        (
            "entitlements".into(),
            Json::Array(c.entitlements.iter().map(|e| s(e)).collect()),
        ),
        ("expiry".into(), Json::Num(c.expiry)),
        ("key_id".into(), s(&kid)),
        ("mark".into(), s(&c.mark)),
        ("not_before".into(), Json::Num(c.not_before)),
        ("product".into(), s(&c.product)),
        ("v".into(), Json::Num(1)),
    ]);
    let sig = issuer.sign_hex(&digest("licence", &write(&msg)));
    let Json::Object(mut o) = msg else {
        return None;
    };
    o.push(("sig".into(), Json::Str(sig)));
    Some(write(&Json::Object(o)))
}
