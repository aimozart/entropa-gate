# ADR 0007: cargo-llvm-cov for coverage
Date: 2026-10-20. Status: accepted (stage S0b).

## Context
STANDARDS.md asks for coverage with a floor.

## Decision
scripts/coverage.sh runs cargo llvm-cov with --fail-under-lines $FLOOR; CI sets the floor.

## Consequences
Co-located #[cfg(test)] tests are counted correctly by this tool, unlike file-based counters.
