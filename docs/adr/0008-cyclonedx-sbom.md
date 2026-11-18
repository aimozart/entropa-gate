# ADR 0008: CycloneDX SBOM via cargo-cyclonedx
Date: 2026-10-20. Status: accepted (stage S0b).

## Context
STANDARDS.md requires an SBOM attached to releases.

## Decision
scripts/sbom.sh writes *.cdx.json per crate (gitignored); CI uploads them as an artifact.

## Consequences
No signing or provenance attestation yet; that needs GitHub OIDC and is a later stage.
