# Verification map

Where the real proof for each kind of claim actually lives in this repo — a front-door index so a
reviewer (human or automated) doesn't have to reconstruct it from a transcript.

## Run the verification set

```bash
cargo test --workspace
./scripts/verify-entropa-persistence.sh   # or scripts/smoke.sh, same script
gitleaks detect --source .
```

Secret scanning is verified **live**, in CI (`entropa-public/.github/workflows/ci.yml`, push + PR)
and in the local pre-commit hook (`.git/hooks/pre-commit`) — never by a committed static scan output,
which would go stale the moment the next commit lands.

## Rust tests (`cargo test --workspace` — 90 passing as of 2026-08-15)

| Behavior | Where |
|---|---|
| Chain rollback / epoch-recovery behavior | `crates/core/src/chain_tests.rs` — `recovers_longest_valid_prefix_after_gap`, `single_missing_block_near_the_end_costs_only_the_tail`, `rollback_detected_flags_only_when_something_was_actually_discarded`, and 15 more |
| Bounded-memory window (O(n) fix) | `crates/core/src/chain_tests.rs` — `repeated_eviction_keeps_memory_flat_regardless_of_total_height`, `bounded_chain_*` |
| Partner dashboard routes | `crates/api/src/routes/dashboard.rs` — happy path, 404, XSS-escaping, ordering |
| `/api/tx` API-key auth (valid/invalid/missing) | `crates/api/src/routes/tx.rs` |
| Receipt verification | `crates/api/src/routes/receipt.rs` |
| Admin panel fail-closed auth | `crates/api/src/admin/auth.rs` |
| NIST FIPS-204 ACVP correctness | `crates/core/tests/nist_kat.rs` (the one file in an actual `tests/` directory) |

See `TESTING.md` for why the test layout is idiomatic Rust (co-located `#[cfg(test)]`), not a
directory-based convention, and why a directory-only test-file count undercounts this repo.

## Security

| Control | Where |
|---|---|
| Secret-scan config (allowlist for known-safe NIST vectors) | `.gitleaks.toml` |
| Secret-scan enforcement, local | `.git/hooks/pre-commit` → `scripts/security/secret-scan.sh` (plain bash, not the Python `pre-commit` framework) |
| Secret-scan enforcement, CI | `entropa-public/.github/workflows/ci.yml` (`secret-scan` job, `gitleaks/gitleaks-action@v3`, push + PR) |
| Dependency-vulnerability scan | `scripts/security/dependency-audit.sh`; CI job `dependency-audit`, push + daily cron |
| Full explanation, known-safe patterns | `SECURITY.md` |

## Live-service smoke check (read-only, never touches consensus/persistence code)

`scripts/verify-entropa-persistence.sh` (aliased `scripts/smoke.sh`) — health, height-climbing,
and a full `Chain::verify()` run against the real live chain data. Exits nonzero on any failure
(`set -euo pipefail` + explicit `fail()`).

## Local CI (this repo doesn't use GitHub/Gitea Actions — see `SECURITY.md` § CI boundary)

`scripts/ci.sh` (also `scripts/verify.sh`, same script — the stable name to reference from
anywhere) — fmt, clippy, `cargo test --workspace`, secret-scan, dependency-audit, one command.

## Observability

`monitoring/` — versioned exports of the 5 live Cloud Monitoring alert policies.
`.env.example` — every environment variable the code actually reads, documented with fake values.

## Decision closure

`a project record (not published)` — every architecture/safety/product decision, in Decision / Reason /
Expected proof / Observed outcome / Evidence / Status form. 17 entries as of 2026-08-15.
