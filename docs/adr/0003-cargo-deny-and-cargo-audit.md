# ADR 0003: cargo-deny and cargo-audit for supply-chain checks
Date: 2026-10-20. Status: accepted (stage S0b).

## Context
STANDARDS.md requires advisory, licence, ban and source checks, and the first run found 11 RustSec advisories.

## Decision
deny.toml (advisories, licences allow-list, bans, sources) and cargo audit both run in scripts/check.sh and CI. allow-wildcard-paths is on because workspace path dependencies carry no version.

## Consequences
Builds fail on new advisories until the lockfile is bumped; this is intended. Two tools overlap on advisories on purpose (different databases and parsers).
