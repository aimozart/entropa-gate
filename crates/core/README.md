# entropa-core

A post-quantum, signed **Merkle transparency log** for [Entropa](https://entropa.space):
append records, sign checkpoints with **ML-DSA-65 (NIST FIPS 204)**, hand out receipts that anyone can verify
with only the signer's public key. Pure Rust, no network calls, no `unsafe`.

- `pqc`: `Probe` identities and ML-DSA signatures, checked against NIST ACVP test vectors (`tests/nist_kat.rs`).
- `merkle`: RFC 6962 style domain-separated leaf/node hashing, inclusion and consistency proofs.
- `transparency_log`: the append-only log, signed checkpoints, receipts, and the versioned, length-prefixed
  record encoding (format v2: different `(payload, label)` records can never share bytes or a leaf hash).
- `signer`: the `CheckpointSigner` trait, so keys can live in-process or in a managed KMS (see `entropa-kms`).

## Quickstart
```rust
use entropa_core::transparency_log::{encode_record, verify_receipt, TransparencyLog};
use entropa_core::Probe;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let signer = Probe::spawn();                         // test key; production signs in a KMS
let mut log = TransparencyLog::new();
let record = encode_record("hash-of-the-decision", Some("loan:approved"))?;
let index = log.append(&record);

let checkpoint = log.checkpoint(&signer, 1_700_000_000);
let receipt = log.receipt(index, &checkpoint).ok_or("no receipt")?;

// A verifier needs only the receipt and the signer's public key.
assert!(verify_receipt(&receipt, &signer.pubkey_hex()));
# Ok(())
# }
```

## Status
Not FIPS-validated: the NIST vectors prove the signatures match the standard, not a CMVP/CAVP certification.
A signature proves who recorded what and that it was not changed; it does not prove a decision was correct.
Version 0.2.0 changed the record encoding (breaking, see CHANGELOG). Licence: MIT.
