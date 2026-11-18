//! Pure verification and explanation over `entropa-core`. No I/O.

use entropa_core::merkle::{leaf_hash, node_hash, verify_inclusion_at, Side};
use entropa_core::transparency_log::{decode_record, Checkpoint, Receipt};
use serde_json::{json, Value};

/// Longest text preview returned for a record payload or label, in characters.
pub const PREVIEW_CHARS: usize = 128;

/// First 16 hex characters of BLAKE3 over the public key bytes (empty for non-hex input).
pub fn key_id(pubkey_hex: &str) -> String {
    match hex::decode(pubkey_hex) {
        Ok(bytes) => hex::encode(&blake3::hash(&bytes).as_bytes()[..8]),
        Err(_) => String::new(),
    }
}

fn clip(s: &str) -> (String, bool) {
    let n = s.chars().count();
    (s.chars().take(PREVIEW_CHARS).collect(), n > PREVIEW_CHARS)
}

/// Data-minimal preview of record bytes. The text is untrusted and says so.
pub fn record_preview(bytes: &[u8]) -> Value {
    match decode_record(bytes) {
        Ok((payload, label)) => {
            let (p, truncated) = clip(&payload);
            let (l, l_truncated) = label
                .as_deref()
                .map(clip)
                .map_or((None, false), |(l, t)| (Some(l), t));
            json!({
                "decode_ok": true,
                "payload_preview": p,
                "payload_truncated": truncated,
                "label_preview": l,
                "label_truncated": l_truncated,
                "record_format_version": 2,
                "untrusted_text": true,
            })
        }
        Err(_) => json!({
            "decode_ok": false,
            "payload_preview": "",
            "payload_truncated": false,
            "label_preview": null,
            "label_truncated": false,
            "record_format_version": 2,
            "untrusted_text": true,
        }),
    }
}

fn check(name: &str, passed: bool, detail: &str) -> Value {
    json!({"name": name, "passed": passed, "detail": detail})
}

/// Signature under the checkpoint's own key, and whether that key is trusted.
pub fn signature_and_trust(cp: &Checkpoint, trusted: &[String]) -> (bool, bool) {
    let sig = cp.verify_signature(&cp.proposer_pubkey);
    (sig, sig && trusted.contains(&cp.proposer_pubkey))
}

/// `verify_checkpoint` output.
pub fn verify_checkpoint(cp: &Checkpoint, trusted: &[String]) -> Value {
    let (sig, is_trusted) = signature_and_trust(cp, trusted);
    let claimed = key_id(&cp.proposer_pubkey);
    json!({
        "signature_valid": sig,
        "signer_trusted": is_trusted,
        "claimed_key_id": claimed,
        "trusted_key_id": if is_trusted { json!(claimed) } else { Value::Null },
        "size": cp.size,
        "root": hex::encode(cp.root),
        "digest_layout": "root(32)||size(u64be)||timestamp(u64be)",
        "checks": [
            check("signature_under_embedded_key", sig, if sig { "the signature verifies under the key inside the checkpoint" } else { "the signature does not verify under the key inside the checkpoint" }),
            check("signer_in_trust_store", is_trusted, if is_trusted { "the key is in the configured trust store" } else { "the key is not in the configured trust store (or the signature is invalid)" }),
        ],
    })
}

/// `verify_receipt` output. `head` is the source's current head, when there is one.
pub fn verify_receipt(r: &Receipt, trusted: &[String], head: Option<&Checkpoint>) -> Value {
    let (sig, is_trusted) = signature_and_trust(&r.checkpoint, trusted);
    let leaf = leaf_hash(&r.record);
    let in_range = r.index < r.checkpoint.size;
    let inclusion = verify_inclusion_at(
        &leaf,
        r.index,
        r.checkpoint.size,
        &r.proof,
        &r.checkpoint.root,
    );
    let matches_head = head.map(|h| h.root == r.checkpoint.root && h.size == r.checkpoint.size);
    json!({
        "valid": sig && is_trusted && inclusion,
        "signature_valid": sig,
        "signer_trusted": is_trusted,
        "inclusion_valid": inclusion,
        "index_checked": "bound_to_proof",
        "index": r.index,
        "checkpoint_size": r.checkpoint.size,
        "leaf_hash": hex::encode(leaf),
        "record": record_preview(&r.record),
        "matches_current_head": matches_head,
        "checks": [
            check("signature_under_embedded_key", sig, "checkpoint signature under the key inside the checkpoint"),
            check("signer_in_trust_store", is_trusted, "that key is in the configured trust store"),
            check("index_in_range", in_range, "0 <= index < checkpoint size"),
            check("inclusion_path", inclusion, "the audit path for this index and tree size leads from the record's leaf hash to the checkpoint root"),
        ],
    })
}

fn short(h: &[u8; 32]) -> String {
    hex::encode(&h[..4])
}

/// `explain_proof` output: the Merkle walk, step by step. Does not check the signature.
pub fn explain_proof(r: &Receipt) -> Value {
    let mut steps = Vec::with_capacity(r.proof.len() + 2);
    let mut cur = leaf_hash(&r.record);
    steps.push(json!({
        "n": 1, "operation": "leaf_hash", "formula": "BLAKE3(0x00 || record_bytes)",
        "inputs": [], "output": hex::encode(cur),
    }));
    let mut narrative = format!(
        "1. Leaf hash of the {}-byte record: {}.",
        r.record.len(),
        short(&cur)
    );
    for (i, p) in r.proof.iter().enumerate() {
        let (formula, next) = match p.side {
            Side::Left => (
                "BLAKE3(0x01 || sibling || current)",
                node_hash(&p.sibling, &cur),
            ),
            Side::Right => (
                "BLAKE3(0x01 || current || sibling)",
                node_hash(&cur, &p.sibling),
            ),
        };
        let side = if p.side == Side::Left {
            "Left"
        } else {
            "Right"
        };
        steps.push(json!({
            "n": i + 2, "operation": "combine", "side": side, "formula": formula,
            "inputs": [hex::encode(p.sibling), hex::encode(cur)], "output": hex::encode(next),
        }));
        if narrative.len() < 3500 {
            narrative += &format!(
                " {}. Combine with the {} sibling {}: {}.",
                i + 2,
                side.to_lowercase(),
                short(&p.sibling),
                short(&next)
            );
        }
        cur = next;
    }
    let matches = cur == r.checkpoint.root;
    steps.push(json!({
        "n": r.proof.len() + 2, "operation": "compare", "formula": "computed root == checkpoint.root",
        "inputs": [hex::encode(cur), hex::encode(r.checkpoint.root)], "output": matches.to_string(),
    }));
    if matches {
        narrative += " The computed root equals the checkpoint root.";
        let leaf = leaf_hash(&r.record);
        if !verify_inclusion_at(
            &leaf,
            r.index,
            r.checkpoint.size,
            &r.proof,
            &r.checkpoint.root,
        ) {
            narrative += " Note: the hashes combine to the root, but this path does not fit the claimed index and tree size.";
        }
    } else {
        narrative += &format!(
            " Root mismatch: computed {} but the checkpoint says {}.",
            short(&cur),
            short(&r.checkpoint.root)
        );
    }
    narrative.truncate(4000);
    json!({"steps": steps, "root_matches": matches, "signature_checked": false, "narrative": narrative})
}
