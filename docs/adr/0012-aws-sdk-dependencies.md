# ADR 0012: aws-sdk-kms, aws-config and tokio as optional dependencies of entropa-kms
Date: 2026-10-20. Status: accepted (stage S1).

## Context
Production checkpoints must be signed by the ML-DSA-65 key in AWS KMS (alias/entropa-checkpoint-signer, us-west-2). The `KmsClient` trait is the seam; we need a real implementation.

## Decision
Add `aws-sdk-kms` (the official SDK; the only maintained client with `ML_DSA_SHAKE_256` support), `aws-config` with `default-features = false` (we use only its environment credentials provider, region, retry and timeout types; this also keeps the SSO and profile machinery out of the build) and `tokio` (features `rt`, `time` only, because the SDK is async), all `optional = true`, and `aws-sdk-kms` with `default-features = false, features = ["default-https-client", "rt-tokio"]` because its default `rustls` feature pulls the legacy rustls 0.21 / h2 0.3 stack, which carries 7 open RustSec advisories (found by cargo-audit on 2026-10-20); the `default-https-client` path uses rustls 0.23 and is clean behind the cargo feature `aws`. The default build compiles none of them (proved with `cargo tree`, docs/evidence/s1-cargo-tree.txt). Licences are Apache-2.0/MIT, which deny.toml allows.

## Consequences
Roughly 150 extra crates when the feature is on, all checked by cargo-deny and cargo-audit in check.sh (which now also runs with `--all-features`). Credentials are never handled by our code: they come from the standard environment variables.
