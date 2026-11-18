# ADR 0010: cargo-semver-checks for published crates
Date: 2026-10-20. Status: accepted (stage S0b).

## Context
entropa-core is meant to be consumed; accidental breaking changes must be caught.

## Decision
Installed in the dev image. Not yet wired into check.sh because nothing is published and it needs a baseline version.

## Consequences
Revisit at the first release tag.
