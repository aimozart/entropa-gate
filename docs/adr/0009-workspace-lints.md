# ADR 0009: Workspace lints and toolchain pin
Date: 2026-10-20. Status: accepted (stage S0b).

## Context
Unsafe code, undocumented public API and panics on untrusted input are the classes of defect we most want to exclude.

## Decision
Workspace lints: forbid unsafe_code, warn missing_docs, warn unwrap/expect/panic (tests exempt via clippy.toml and file-level allows), deny dbg!/todo!/unimplemented!. Run with -D warnings so warnings fail the gate. entropa-api opts out of the strict set for now (see AUDIT-STANDARDS.md F3).

## Consequences
Strict lints apply to core and kms only until the legacy api crate is pruned or documented.
