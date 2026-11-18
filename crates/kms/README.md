# entropa-kms

Checkpoint signing for [`entropa-core`](https://crates.io/crates/entropa-core) with a managed **ML-DSA-65** key.
`KmsSigner` implements `entropa_core::CheckpointSigner` over any `KmsClient`; verifiers keep using plain
`entropa_core::verify_hex`. Every checkpoint signature is verified before it is returned, and wrong-length keys or
signatures from a client are rejected.

The default build has no cloud dependency. The `aws` feature adds `AwsKmsClient` (aws-sdk-kms, credentials from the
standard `AWS_*` environment variables only, `ML_DSA_SHAKE_256` raw signing, messages up to 4096 bytes).

## Quickstart (any client, shown with an in-process stand-in)
```rust
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::{CheckpointSigner, Probe};
use entropa_kms::{KeySpec, KmsClient, KmsError, KmsSigner};

struct Stub(Probe); // a real deployment implements KmsClient over a managed key
impl KmsClient for Stub {
    fn public_key_raw(&self) -> Result<Vec<u8>, KmsError> {
        hex::decode(self.0.pubkey_hex()).map_err(|e| KmsError(e.to_string()))
    }
    fn sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, KmsError> {
        hex::decode(self.0.sign_hex(msg)).map_err(|e| KmsError(e.to_string()))
    }
}

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let signer = KmsSigner::new(Stub(Probe::spawn()), KeySpec::MlDsa65)?;
let mut log = TransparencyLog::new();
log.append(b"record");
let cp = log.checkpoint_with(&signer, 1_700_000_000)?;
assert!(cp.verify_signature(&signer.pubkey_hex()));
# Ok(())
# }
```
Licence: MIT.
