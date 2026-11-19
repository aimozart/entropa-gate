# Architecture (re-rust, as of 2026-10-20)
Facts only: planned parts are marked *planned* and do not exist in this repository yet. The earlier product-era architecture (Cloud Run validators, quorum, Java services) is in git history and `docs/archive/`.

## Components
```
 record (payload, label?)          checkpoint                      receipt
        |                               |                              |
 encode_record (format v2) --> TransparencyLog --> CheckpointSigner --> verify_receipt(receipt, pubkey)
        crates/core                crates/core        Probe (in process)      needs only the public key
                                                      KmsSigner -> KmsClient
                                                      crates/kms   AwsKmsClient (feature aws) -> AWS KMS ML-DSA-65 key
```
- **entropa-core** (library, publishable): `merkle` (domain-separated hashing, inclusion and consistency proofs), `pqc` (ML-DSA-65 `Probe`, `verify_hex`), `signer` (`CheckpointSigner`, `SignError`), `transparency_log` (log, checkpoints, receipts, record format v2, `AppendOnlyStore`). No network calls, no `unsafe` (workspace lint `forbid`). Panics on untrusted input are avoided in library paths (clippy `unwrap_used`, `expect_used`, `panic` are warned and built with `-D warnings`).
- **entropa-kms** (library, publishable): `KmsClient` trait (public key, raw sign), `KmsSigner` (validates key and signature lengths), `raw_key_from_spki`, and with feature `aws` an `AwsKmsClient` (synchronous over a private tokio runtime, ADR 0013; credentials only from `AWS_*` environment variables; `ML_DSA_SHAKE_256`, raw messages up to 4096 bytes).
- **entropa-mcp** (unpublished): read-only MCP server over stdio built on `rmcp` 3.6.0 (ADR 0017). A pure library core (`Server::call_at`: strict argument validation, verification over entropa-core, explanations, sliding-window rate limits) plus a thin binary. Trust comes only from `ENTROPA_TRUSTED_PUBKEYS`; the log comes from an exported JSON file (`ENTROPA_LOG_FILE`). It has no dependency on entropa-kms, AWS or an HTTP client (`docs/evidence/s2c-cargo-tree.txt`). Spec: `docs/ARCHITECTURE-MCP.md`.
- **entropa-approvals** (unpublished): signed approval events (ML-DSA-65 through `CheckpointSigner`) written as record-format-v2 payloads labelled `approval.*`; an actor directory; a replay that applies the validity rules (no self-approval, first decision final, expiry, clock skew, revocation by log index); a pure gate bound to action class and exact subject hash, single use. Reads the log through the new read-only `TransparencyLog::record`. Spec `docs/ARCHITECTURE-APPROVALS.md`.
- **entropa-api** (unpublished, legacy): ingest endpoint (`POST /api/tx`, returns 202 with a tracking id), a queue-fed sequencer, Firestore persistence, a partner directory, an admin panel and customer dashboard from the earlier product. Billing and Stripe were removed (S0c1, S0c2). It is slated to be pruned or reshaped; it does not meet the strict lints (`docs/AUDIT-STANDARDS.md` F3). Nothing in this branch deploys it.

## Record format v2 (docs/adr/0011-record-encoding-v2.md)
`0x02 || u32be(len payload) || payload || flag || [u32be(len label) || label]`, flag 0 = no label, 1 = label. Payload and label are UTF-8, at most 1 MiB each. The strict decoder accepts exactly what the encoder produces, so each record has one byte string and one leaf hash (`None` and `Some("")` differ). Leaf hash = BLAKE3(0x00 || bytes); node hash = BLAKE3(0x01 || left || right).

## Checkpoints and receipts
A checkpoint signs `root (32) || size (u64 BE) || timestamp (u64 BE)` (48 bytes, well under the 4096-byte KMS raw limit). `checkpoint_with` refuses to return a checkpoint whose signature does not verify under the signer's reported public key. A receipt bundles the record bytes, the inclusion proof and the checkpoint; `verify_receipt` checks the signature against a public key the verifier already trusts, then the proof.

## Quality harness
Pinned toolchain (`rust-toolchain.toml`, 1.99.1), workspace lints, cargo-deny and cargo-audit, property tests, two fuzz targets, mutation testing, coverage, SBOM, a CI workflow and a tag-triggered Trusted Publishing release workflow (both written, never run on GitHub). Everything runs in the Docker dev image. Details: `docs/STANDARDS.md`, `docs/adr/`, `TESTING.md`.

## Planned (not in this repository yet)
MCP hardening and enforcement, signed approval records and human gate, Cedar default-deny policy gate, witness that checks checkpoint consistency, CI and infrastructure as code with priced resources, a public explorer with no login and data-minimal records. Cloud footprint today: one AWS KMS key (us-west-2, `the cost notes`); nothing else is running.

## Threats
`docs/THREAT-MODEL.md` (STRIDE per component). Known open issues: `docs/AUDIT-STANDARDS.md`.
