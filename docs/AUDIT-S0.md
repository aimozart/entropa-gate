# S0 audit report ( 2026-10-20)

Scope: diff of the baseline vs entropa-chain 253d662 for crates/core/src/signer.rs, `TransparencyLog::checkpoint_with`, crates/kms.
Baseline: 244 passed, 0 failed, 4 ignored. Final: 251 passed, 0 failed, 4 ignored. clippy -D warnings and fmt --check clean.

## Findings (all three proven by a red test, then fixed minimally)
1. **KmsSigner::new accepted a public key of any length** (red: `audit_a_wrong_length_public_key_from_the_client_is_rejected_at_construction`, `is_err()` assertion failed). Checkpoints would have carried an unverifiable pubkey. Fix: length must be 1952 bytes.
2. **KmsSigner::try_sign_hex accepted a signature of any length** (red: `audit_a_wrong_length_signature_from_the_client_is_rejected`). Fix: must be 3309 bytes (new const `ML_DSA_65_SIGNATURE_BYTES`).
3. **checkpoint_with returned a checkpoint whose signature did not verify under the reported pubkey** (red: `audit_checkpoint_with_rejects_a_signature_that_does_not_verify_under_the_reported_pubkey`). Fix: verify with `verify_hex` before returning, error `SignError::Backend`. Cost: one ML-DSA verify per checkpoint (decision for the owner/the reviewer if that matters at volume; it protects every backend).

## Guards that passed immediately (behaviour already correct)
- Empty log signs and verifies (size 0).
- Empty log and a log of one empty record share a root but sign different digests (size is in the digest).
- `u64::MAX` timestamp; message exactly 4096 bytes; empty message.
- SPKI: flipped prefix bit, length +1/-1, prefix only all rejected.

## Risks noted, not changed
- `checkpoint()` (Probe) and `checkpoint_with` duplicate logic; consider delegating later.
- `checkpoint_digest` uses `usize::to_be_bytes` for size, so the digest is 8 bytes on 64-bit but 4 on 32-bit targets.
- `raw_key_from_spki` is not called by `KmsSigner` (the client is trusted to strip SPKI); S1 must call it.

## Could not check
No cloud calls (per constraints), so the real KMS client, throttling and the live key were not exercised; only the captured vector.
