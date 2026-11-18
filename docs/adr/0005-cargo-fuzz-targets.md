# ADR 0005: cargo-fuzz for parsers and deserializers
Date: 2026-10-20. Status: accepted (stage S0b).

## Context
Every parser of untrusted bytes needs a fuzz target (STANDARDS.md).

## Decision
crates/core/fuzz (excluded from the workspace, nightly) has decode_record and receipt_json. scripts/fuzz.sh runs a time-boxed smoke; CI runs it nightly.

## Consequences
Needs nightly in the image. The first run found finding F4 (NUL separator collision), recorded in docs/AUDIT-STANDARDS.md.
