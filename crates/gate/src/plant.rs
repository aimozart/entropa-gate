//! A TEST HELPER (feature `plant`): rewrite `DIR/ledger/checkpoints.log` with a hand-made chain of checkpoints, signed with the ledger's own key or another seed, so attacked ledgers can be planted
//! the way the adversary of docs/THREAT-MODEL-OPERATOR.md can make them (a regressing clock, a skipped counter, a wrong previous digest, a downgrade, a planted root, another signer).
//! Spec: `{"signer_seed": "<64 hex, optional>", "checkpoints": [{"v": 1|2, "size": N, "time": T, "counter": C?, "prev": "<64 hex>"?, "root": "<64 hex>"?}, ...]}`; for v2 the counter defaults to
//! the previous v2 counter plus one, `prev` to the chain digest of the previous v2 checkpoint of the spec (zero for the first), `root` to the Merkle root of the first `size` records.
//! Nothing is written unless the whole spec is valid.
use crate::{keys, GateError, Res};
use entropa_core::anchor::sign_v2;
use entropa_core::merkle::{self, Hash};
use entropa_core::transparency_log::Checkpoint;
use entropa_core::Probe;
use entropa_ledger::read_raw;
use entropa_witness::strict_json;
use serde_json::Value;
use std::path::Path;

fn bad<T>(what: &str) -> Res<T> {
    Err(GateError::Invalid(format!("plant: {what}")))
}

fn hash(v: &Value) -> Option<Hash> {
    let s = v.as_str()?;
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// Replace the checkpoints of the ledger in `dir` by the ones described in `spec_json`; returns how many lines were written.
pub fn plant(dir: &Path, spec_json: &str) -> Res<usize> {
    let spec = strict_json::from_str(spec_json).or_else(|_| bad("the spec is not valid JSON"))?;
    let Some(top) = spec.as_object() else {
        return bad("the spec is not an object");
    };
    if top.keys().any(|k| k != "checkpoints" && k != "signer_seed") {
        return bad("unknown top-level key");
    }
    let Some(list) = top.get("checkpoints").and_then(Value::as_array) else {
        return bad("checkpoints must be a list");
    };
    let signer = match top.get("signer_seed") {
        None => keys::load(dir)?,
        Some(v) => v
            .as_str()
            .and_then(Probe::from_signing_key_hex)
            .map_or_else(|| bad("signer_seed is not a valid seed"), Ok)?,
    };
    let raw = read_raw(&dir.join("ledger")).or_else(|_| bad("the ledger cannot be read"))?;
    let mut lines: Vec<String> = Vec::new();
    let mut last_v2: Option<entropa_core::anchor::CheckpointV2> = None;
    for e in list {
        let Some(m) = e.as_object() else {
            return bad("a checkpoint is not an object");
        };
        let version = m.get("v").and_then(Value::as_u64);
        let allowed: &[&str] = match version {
            Some(1) => &["v", "size", "time", "root"],
            Some(2) => &["v", "size", "time", "root", "counter", "prev"],
            _ => return bad("v must be 1 or 2"),
        };
        if m.keys().any(|k| !allowed.contains(&k.as_str())) {
            return bad("unknown key in a checkpoint");
        }
        let Some(size) = m
            .get("size")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
        else {
            return bad("size is required");
        };
        let Some(time) = m.get("time").and_then(Value::as_u64) else {
            return bad("time is required");
        };
        if size > raw.leaves.len() {
            return bad("size is beyond the records");
        }
        let root = match m.get("root") {
            Some(v) => hash(v).map_or_else(|| bad("root is not 64 hex digits"), Ok)?,
            None if size == 0 => merkle::leaf_hash(&[]),
            None => merkle::root(&raw.leaves[..size]).map_or_else(|| bad("empty tree"), Ok)?,
        };
        if version == Some(1) {
            // v1 signs root || size (8 bytes, big-endian) || time (8 bytes, big-endian)
            let mut digest = Vec::with_capacity(48);
            digest.extend_from_slice(&root);
            digest.extend_from_slice(&(size as u64).to_be_bytes());
            digest.extend_from_slice(&time.to_be_bytes());
            let cp = Checkpoint {
                root,
                size,
                timestamp: time,
                proposer_pubkey: signer.pubkey_hex(),
                signature: signer.sign_hex(&digest),
            };
            lines.push(serde_json::to_string(&cp).or_else(|_| bad("encoding"))?);
        } else {
            let counter = match m.get("counter") {
                Some(v) => v
                    .as_u64()
                    .map_or_else(|| bad("counter is not a number"), Ok)?,
                None => last_v2.as_ref().map_or(1, |p| p.counter + 1),
            };
            let prev = match m.get("prev") {
                Some(v) => hash(v).map_or_else(|| bad("prev is not 64 hex digits"), Ok)?,
                None => last_v2
                    .as_ref()
                    .map_or([0u8; 32], entropa_core::anchor::CheckpointV2::chain_digest),
            };
            let cp = sign_v2(&signer, counter, &prev, &root, size, time)
                .or_else(|_| bad("signing failed"))?;
            lines.push(serde_json::to_string(&cp).or_else(|_| bad("encoding"))?);
            last_v2 = Some(cp);
        }
    }
    let path = dir.join("ledger/checkpoints.log");
    let tmp = dir.join("ledger/checkpoints.log.plant");
    std::fs::write(
        &tmp,
        lines.iter().map(|l| format!("{l}\n")).collect::<String>(),
    )
    .or_else(|_| bad("cannot write"))?;
    std::fs::rename(&tmp, &path).or_else(|_| bad("cannot replace the checkpoints file"))?;
    Ok(lines.len())
}
