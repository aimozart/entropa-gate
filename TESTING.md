# Testing

## True counts (2026-10-20)
Produced by `scripts/count-tests.sh` (it runs `cargo test --workspace --locked` in Docker, default and `--all-features`, and sums the `test result:` lines). Output saved in `docs/evidence/s0c3-count-tests.txt`.

| Build | Passed | Failed | Ignored |
|---|---|---|---|
| default features | 502 | 0 | 4 |
| `--all-features` (adds the AWS client tests) | 513 | 0 | 5 |

Per crate (default features): entropa_api 129, entropa_core 70 (69 unit plus 1 README doc test), entropa_kms 17 (16 unit plus 1 README doc test), `aws_kms_vector` 3, `nist_kat` 5, `properties` 6, `record_encoding` 12, `transparency_log_prototype` 16; the agent guard (28 S2g tests plus 1 added, 2 path unit tests; implemented in S2h); entropa-approvals (events 5, flow 14, log 4, attestation_scope 2, boundaries 10, static guards 2); entropa-mcp: `entropa_mcp` unit 8 (rate limiter 3, bounded line pump 4, outcome helper 1), `mutation_gaps` 12, `head_and_checkpoint` 13, `receipt_and_explain` 13, `records_hostile_rate` 15, `protocol` 11 (real binary over stdio), `static_checks` 2. The ignored ones are 4 slow real-scale benchmarks in entropa-core and, with `--all-features`, the live AWS KMS test (`aws_live`, needs credentials and `ENTROPA_KMS_KEY_ID`; it ran once on 2026-10-20: a stage record (not published)).

## Why a file count undercounts this repository
Most tests are co-located with the code in `#[cfg(test)] mod tests` blocks (30 source files), which is the idiomatic Rust layout. A tool that only counts files under `tests/` sees 6 integration files and misses the other ~200 tests. Tests have not been moved to be counted. Do not estimate coverage from file names or `grep '#\[test\]'`: the grep also counts tests that only compile with a feature or inside `proptest!` macros, so it will not equal the run. Use the command below.

## Commands
```
./scripts/count-tests.sh      # true counts, per crate and total, both builds
./scripts/check.sh            # the whole gate: fmt, clippy (default + all-features), tests, doc, cargo-deny, cargo-audit, site links
./scripts/coverage.sh         # line coverage (cargo-llvm-cov); core and kms are 89-100%, the legacy api crate lowers the total
./scripts/mutants.sh          # mutation testing on entropa-core, entropa-kms (195 of 196 viable caught) and entropa-mcp (151 of 156 viable caught, 4 documented survivors)
./scripts/fuzz.sh decode_record 60   # fuzz smoke; targets: decode_record, receipt_json
./scripts/secret-scan.sh      # gitleaks over the tree and full history
```
Everything runs in Docker (`tools/Dockerfile.dev`); Rust and Node are not installed on the build PC. Containers carry hard limits (24g memory, 12 CPUs, 4096 processes by default, overridable) and mutation runs use `--jobs 2 --timeout 30`: see docs/DEV-CONTAINER-LIMITS.md; `scripts/tests/container-limits.sh` proves them.

## Kinds of tests
- Unit tests next to the code, written red first (evidence of each red run is under `docs/evidence/`).
- Known-answer vectors: NIST ACVP ML-DSA-65 (`crates/core/tests/nist_kat.rs`), the captured AWS KMS vector, and the record v2 golden vectors (all public test data, see the `tests/vectors/` READMEs).
- Property tests (proptest) for Merkle proofs, receipts, record uniqueness and canonical form.
- Fuzz targets for the record decoder and receipt JSON; mutation testing on the core and kms crates.
- Snapshot tests for the JSON contract of the ingest/export API (`crates/api/tests`).
