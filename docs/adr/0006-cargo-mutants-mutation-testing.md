# ADR 0006: cargo-mutants for mutation testing
Date: 2026-10-20. Status: accepted (stage S0b).

## Context
Line coverage does not show whether tests assert anything; mutation testing does.

## Decision
scripts/mutants.sh runs cargo-mutants on entropa-core and entropa-kms; nightly in CI. Surviving mutants are triaged in docs/AUDIT-STANDARDS.md.

## Consequences
Slow (minutes to hours), so not run per push.
