//! Signed revocation lists. Fail closed: no list, an unsigned or untrusted list, or a list older than the maximum age denies everything.

use crate::canon::{parse, write, Json};
use crate::claims::is_hex;
use crate::verify::{digest, sig_ok, Deny, Policy, Trust};
use entropa_core::Probe;

/// Largest revocation list accepted (bytes).
pub const MAX_LIST_BYTES: usize = 64 * 1024;

/// Why a token was revoked (closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The token or its key is believed stolen.
    Compromise,
    /// The holder asked for it.
    Requested,
    /// A new token replaces it.
    Superseded,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Reason::Compromise => "compromise",
            Reason::Requested => "requested",
            Reason::Superseded => "superseded",
        }
    }
    fn parse(s: &str) -> Option<Reason> {
        match s {
            "compromise" => Some(Reason::Compromise),
            "requested" => Some(Reason::Requested),
            "superseded" => Some(Reason::Superseded),
            _ => None,
        }
    }
}

fn message(issued_at: u64, key_id: &str, entries: &[(String, u64, Reason)]) -> Json {
    Json::Object(vec![
        (
            "entries".into(),
            Json::Array(
                entries
                    .iter()
                    .map(|(id, at, r)| {
                        Json::Object(vec![
                            ("reason".into(), Json::Str(r.as_str().into())),
                            ("revoked_at".into(), Json::Num(*at)),
                            ("token_id".into(), Json::Str(id.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("issued_at".into(), Json::Num(issued_at)),
        ("key_id".into(), Json::Str(key_id.into())),
        ("kind".into(), Json::Str("revocations".into())),
        ("v".into(), Json::Num(1)),
    ])
}

/// Sign a revocation list (entries are sorted by token id).
pub fn issue_revocations(
    signer: &Probe,
    issued_at: u64,
    entries: &[(String, u64, Reason)],
) -> Vec<u8> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let kid = crate::verify::key_id_of(&signer.pubkey_hex()).unwrap_or_default();
    let msg = message(issued_at, &kid, &sorted);
    let sig = signer.sign_hex(&digest("revocations", &write(&msg)));
    let Json::Object(mut o) = msg else {
        return Vec::new();
    };
    o.push(("sig".into(), Json::Str(sig)));
    write(&Json::Object(o))
}

/// A signed list with no entries.
pub fn empty_revocations(signer: &Probe, issued_at: u64) -> Vec<u8> {
    issue_revocations(signer, issued_at, &[])
}

/// Read and check a list; returns the revoked token ids.
pub(crate) fn read_revocations(
    bytes: &[u8],
    trust: &Trust,
    p: &Policy,
) -> Result<Vec<String>, Deny> {
    let bad = Deny::RevocationInvalid;
    if bytes.len() > MAX_LIST_BYTES {
        return Err(bad);
    }
    let j = parse(bytes).map_err(|_| bad)?;
    if write(&j) != bytes {
        return Err(bad);
    }
    if !j.has_exactly(&["entries", "issued_at", "key_id", "kind", "sig", "v"]) {
        return Err(bad);
    }
    if j.get("v").and_then(Json::as_u64) != Some(1)
        || j.get("kind").and_then(Json::as_str) != Some("revocations")
    {
        return Err(bad);
    }
    let kid = j.get("key_id").and_then(Json::as_str).ok_or(bad)?;
    let issued_at = j.get("issued_at").and_then(Json::as_u64).ok_or(bad)?;
    let sig = j.get("sig").and_then(Json::as_str).ok_or(bad)?;
    let pk = trust.get(kid).ok_or(bad)?;
    let mut entries: Vec<(String, u64, Reason)> = Vec::new();
    let Some(Json::Array(list)) = j.get("entries") else {
        return Err(bad);
    };
    for e in list {
        if !e.has_exactly(&["reason", "revoked_at", "token_id"]) {
            return Err(bad);
        }
        let id = e.get("token_id").and_then(Json::as_str).ok_or(bad)?;
        let at = e.get("revoked_at").and_then(Json::as_u64).ok_or(bad)?;
        let reason = e
            .get("reason")
            .and_then(Json::as_str)
            .and_then(Reason::parse)
            .ok_or(bad)?;
        if !is_hex(id, 32) || entries.last().is_some_and(|l| l.0.as_str() >= id) {
            return Err(bad);
        }
        entries.push((id.to_string(), at, reason));
    }
    let msg = message(issued_at, kid, &entries);
    if !sig_ok(pk, &digest("revocations", &write(&msg)), sig) {
        return Err(bad);
    }
    if issued_at > p.now.saturating_add(p.skew) {
        return Err(bad);
    }
    if p.now.saturating_sub(issued_at) > p.rev_max_age {
        return Err(Deny::RevocationStale);
    }
    Ok(entries.into_iter().map(|e| e.0).collect())
}

/// Fail-closed revocation check for a set of token ids (the token, its parent, its root).
pub(crate) fn check_revocation(
    ids: &[&str],
    list: Option<&[u8]>,
    trust: &Trust,
    p: &Policy,
) -> Result<(), Deny> {
    let bytes = list.ok_or(Deny::RevocationMissing)?;
    let revoked = read_revocations(bytes, trust, p)?;
    if ids.iter().any(|id| revoked.iter().any(|r| r == id)) {
        return Err(Deny::Revoked);
    }
    Ok(())
}
