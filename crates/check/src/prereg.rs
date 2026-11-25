//! The pre-registration `entropa-prereg-v1` (signed with ML-DSA-65, domain-separated).
use crate::Refusal;
use std::path::Path;

/// The fixed tag that starts the signed bytes.
pub const TAG: &[u8] = b"entropa-prereg-v1\0";

/// The four hashes a pre-registration commits to (lowercase hex sha256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    /// The set file.
    pub set: String,
    /// The forecast file.
    pub forecast: String,
    /// The runner binary.
    pub runner: String,
    /// The target file.
    pub target: String,
}

/// The bytes that are signed for a record: the tag, then the canonical JSON (sorted keys, no spaces) without the signature.
pub fn signed_bytes(stage: &str, h: &Hashes, pubkey_hex: &str) -> Vec<u8> {
    let q = |s: &str| serde_json::to_string(s).unwrap_or_default();
    let body = format!(
        "{{\"forecast_sha256\":{},\"pubkey\":{},\"runner_sha256\":{},\"schema\":\"entropa-prereg-v1\",\"set_sha256\":{},\"stage\":{},\"target_sha256\":{}}}",
        q(&h.forecast), q(pubkey_hex), q(&h.runner), q(&h.set), q(stage), q(&h.target)
    );
    let mut out = TAG.to_vec();
    out.extend_from_slice(body.as_bytes());
    out
}

fn hash_ok(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Make a signed record (JSON text). `not_key_ids` lists release key ids the key must NOT equal.
pub fn make(
    stage: &str,
    h: &Hashes,
    key_file: &Path,
    not_key_ids: &[String],
) -> Result<String, Refusal> {
    if !crate::name_ok(stage)
        || ![&h.set, &h.forecast, &h.runner, &h.target]
            .iter()
            .all(|x| hash_ok(x))
    {
        return Err(Refusal::new("the stage or a hash is malformed"));
    }
    let probe = entropa_release::cli::load_key(key_file).map_err(Refusal)?;
    let pk = probe.pubkey_hex();
    let id = entropa_release::cli::key_id(&pk);
    if not_key_ids.contains(&id) {
        return Err(Refusal::new(
            "this key equals a release key (a pre-registration key must be a different key)",
        ));
    }
    let sig = probe.sign_hex(&signed_bytes(stage, h, &pk));
    Ok(serde_json::json!({
        "schema": "entropa-prereg-v1", "stage": stage, "set_sha256": h.set, "forecast_sha256": h.forecast,
        "runner_sha256": h.runner, "target_sha256": h.target, "pubkey": pk, "signature": sig
    })
    .to_string())
}

/// Verify a record under `pubkey_hex` and return its stage and hashes.
pub fn verify(record: &str, pubkey_hex: &str) -> Result<(String, Hashes), Refusal> {
    let v = crate::strict(record.as_bytes())?;
    let o = v
        .as_object()
        .ok_or_else(|| Refusal::new("the record is not an object"))?;
    let want = [
        "schema",
        "stage",
        "set_sha256",
        "forecast_sha256",
        "runner_sha256",
        "target_sha256",
        "pubkey",
        "signature",
    ];
    if o.len() != want.len() || want.iter().any(|k| !o.contains_key(*k)) {
        return Err(Refusal::new(
            "the record does not have exactly the fields of entropa-prereg-v1",
        ));
    }
    let s = |k: &str| {
        o.get(k)
            .and_then(|x| x.as_str())
            .map(String::from)
            .ok_or_else(|| Refusal::new("a record field is not a string"))
    };
    if s("schema")? != "entropa-prereg-v1" {
        return Err(Refusal::new("the schema is not entropa-prereg-v1"));
    }
    let stage = s("stage")?;
    let h = Hashes {
        set: s("set_sha256")?,
        forecast: s("forecast_sha256")?,
        runner: s("runner_sha256")?,
        target: s("target_sha256")?,
    };
    if !crate::name_ok(&stage)
        || ![&h.set, &h.forecast, &h.runner, &h.target]
            .iter()
            .all(|x| hash_ok(x))
    {
        return Err(Refusal::new(
            "the stage or a hash in the record is malformed",
        ));
    }
    if s("pubkey")? != pubkey_hex {
        return Err(Refusal::new(
            "the record was not signed by the given public key",
        ));
    }
    if !entropa_core::verify_hex(
        pubkey_hex,
        &signed_bytes(&stage, &h, pubkey_hex),
        &s("signature")?,
    ) {
        return Err(Refusal::new("the signature does not verify"));
    }
    Ok((stage, h))
}
