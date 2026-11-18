# ADR 0013: synchronous KmsClient over a private current-thread tokio runtime
Date: 2026-10-20. Status: accepted (stage S1).

## Context
`KmsClient` and `CheckpointSigner` are synchronous (the log core has no async). The AWS SDK is async.

## Decision
`AwsKmsClient` owns a small `tokio` current-thread runtime and `block_on`s each call, with explicit per-attempt and overall timeouts and the SDK's standard retry mode.

## Consequences
Simple, no async leaking into the core. Trade-off: calling it from inside another tokio runtime's worker thread panics ("cannot start a runtime from within a runtime"); async callers (the api crate) must use `spawn_blocking`. If signing latency or concurrency becomes a bottleneck, add an async trait later. Accepted for now: checkpoints are infrequent.
