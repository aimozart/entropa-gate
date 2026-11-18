//! Design A: one signed token. Narrowing means the issuer signs a new, narrower token whose `parent` names the old one.

use crate::canon::{parse, write, CanonError, Json};
use crate::claims::{check_narrower, is_hex, Claims};
use crate::revoke::check_revocation;
use crate::verify::{check_policy, digest, key_id_of, sig_ok, Deny, Policy, Trust, Verified, ALG};
use crate::IssueError;
use entropa_core::Probe;

/// Largest design A token accepted (bytes).
pub const MAX_A_BYTES: usize = 64 * 1024;

pub(crate) fn canon_deny(e: CanonError) -> Deny {
    match e {
        CanonError::TooLarge => Deny::TooLarge,
        CanonError::DuplicateKey => Deny::DuplicateKey,
        _ => Deny::Malformed,
    }
}

fn message(claims: &Json, key_id: &str) -> Json {
    Json::Object(vec![
        ("alg".into(), Json::Str(ALG.into())),
        ("claims".into(), claims.clone()),
        ("key_id".into(), Json::Str(key_id.into())),
        ("v".into(), Json::Num(1)),
    ])
}

/// Sign a token for these claims.
pub fn issue_a(issuer: &Probe, claims: &Claims) -> Result<Vec<u8>, IssueError> {
    claims.validate().map_err(IssueError::InvalidClaims)?;
    let kid = key_id_of(&issuer.pubkey_hex()).ok_or(IssueError::KeyMismatch)?;
    let msg = message(&claims.to_json(), &kid);
    let sig = issuer.sign_hex(&digest("a-token", &write(&msg)));
    let Json::Object(mut o) = msg else {
        return Err(IssueError::Parse);
    };
    o.push(("sig".into(), Json::Str(sig)));
    let bytes = write(&Json::Object(o));
    if bytes.len() > MAX_A_BYTES {
        return Err(IssueError::TooLarge);
    }
    Ok(bytes)
}

struct ParsedA {
    claims: Claims,
    key_id: String,
    sig: String,
    msg: Json,
}

fn parse_a(bytes: &[u8]) -> Result<ParsedA, Deny> {
    if bytes.len() > MAX_A_BYTES {
        return Err(Deny::TooLarge);
    }
    let j = parse(bytes).map_err(canon_deny)?;
    if write(&j) != bytes {
        return Err(Deny::NotCanonical);
    }
    if !j.has_exactly(&["alg", "claims", "key_id", "sig", "v"]) {
        return Err(Deny::Malformed);
    }
    if j.get("alg").and_then(Json::as_str) != Some(ALG) {
        return Err(if j.get("alg").and_then(Json::as_str).is_some() {
            Deny::BadAlgorithm
        } else {
            Deny::Malformed
        });
    }
    if j.get("v").and_then(Json::as_u64) != Some(1) {
        return Err(Deny::Malformed);
    }
    let key_id = j
        .get("key_id")
        .and_then(Json::as_str)
        .filter(|k| is_hex(k, 16))
        .ok_or(Deny::Malformed)?
        .to_string();
    let sig = j
        .get("sig")
        .and_then(Json::as_str)
        .ok_or(Deny::Malformed)?
        .to_string();
    let cj = j.get("claims").ok_or(Deny::Malformed)?;
    let claims = Claims::from_json(cj)?;
    Ok(ParsedA {
        msg: message(cj, &key_id),
        claims,
        key_id,
        sig,
    })
}

fn signature_ok(t: &ParsedA, trust: &Trust) -> Result<(), Deny> {
    let pk = trust.get(&t.key_id).ok_or(Deny::UnknownKey)?;
    if sig_ok(pk, &digest("a-token", &write(&t.msg)), &t.sig) {
        Ok(())
    } else {
        Err(Deny::BadSignature)
    }
}

/// The issuer re-issues a narrower token: `child` must not exceed the parent on any field; its `parent` is set to the parent's id.
pub fn narrow_a(issuer: &Probe, parent: &[u8], child: &Claims) -> Result<Vec<u8>, IssueError> {
    let p = parse_a(parent).map_err(|_| IssueError::Parse)?;
    let mut c = child.clone();
    c.parent = Some(p.claims.token_id.clone());
    check_narrower(&p.claims, &c).map_err(IssueError::Widened)?;
    issue_a(issuer, &c)
}

/// Verify a design A token offline. `parent`, when given, is checked too (signature, same issuer, and the narrowing law).
pub fn verify_a(
    bytes: &[u8],
    trust: &Trust,
    policy: &Policy,
    revocations: Option<&[u8]>,
    parent: Option<&[u8]>,
) -> Result<Verified, Deny> {
    let t = parse_a(bytes)?;
    signature_ok(&t, trust)?;
    check_policy(&t.claims, policy)?;
    let mut ids: Vec<&str> = vec![t.claims.token_id.as_str()];
    if let Some(p) = &t.claims.parent {
        ids.push(p.as_str());
    }
    let parsed_parent;
    match (&t.claims.parent, parent) {
        (Some(pid), Some(pb)) => {
            parsed_parent = parse_a(pb)?;
            if parsed_parent.claims.token_id != *pid || parsed_parent.key_id != t.key_id {
                return Err(Deny::ParentMismatch);
            }
            signature_ok(&parsed_parent, trust)?;
            check_narrower(&parsed_parent.claims, &t.claims).map_err(|_| Deny::Widened)?;
        }
        (None, Some(_)) => return Err(Deny::ParentMismatch),
        _ => {}
    }
    check_revocation(&ids, revocations, trust, policy)?;
    Ok(Verified {
        token_id: t.claims.token_id.clone(),
        claims: t.claims,
        chain_len: 1,
    })
}
