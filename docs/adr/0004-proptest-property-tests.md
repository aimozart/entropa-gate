# ADR 0004: proptest for property tests
Date: 2026-10-20. Status: accepted (stage S0b).

## Context
Merkle proofs and signers must hold for any size and index, not just hand-picked cases.

## Decision
Add proptest as a dev-dependency of entropa-core and entropa-kms. Properties: inclusion and consistency proofs, receipts, KMS-signed checkpoints.

## Consequences
Dev-only dependency; failing seeds persist in proptest-regressions/ and must be committed.
