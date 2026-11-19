# S0b audit: findings from the standards tooling (2026-10-20)
Final counts: 264 passed, 0 failed, 4 ignored (S0 baseline 251; +6 property tests, +7 mutation-driven tests incl. F4 characterization and the golden digest layout). Evidence: docs/evidence/s0b-check.txt, s0b-coverage.txt, s0b-mutants-fuzz.txt.
Reproduce the true counts (tests are co-located in `#[cfg(test)]` modules, so file-counting tools undercount): `./scripts/check.sh` prints `test result` per crate; sum the `passed` figures.

## Numbers
- Mutation (cargo-mutants, entropa-core + entropa-kms): 212 mutants, 195 caught, 16 unviable, 1 timeout, 0 missed (99.5% of viable; first run 91.4%).
- Coverage (cargo-llvm-cov, `./scripts/coverage.sh`): workspace lines 68.03%, regions 71.87%. core and kms files are 90-100% (merkle 98%, pqc 94%, signer 95%, checkpoint/record/store 100%, kms 97%, transparency_log/mod 89%, batch_receipt 68%); the legacy entropa-api crate drags the total (admin, dashboard/handlers, billing, bins at 0-5%). CI floor set to 65% so it fails on regression, not to hit a target.
- Fuzz (60 s each): decode_record 21,952,428 runs, receipt_json 6,553,128 runs, no crashes after F4 handling.
- Supply chain: cargo-deny (advisories, bans, licences, sources) ok; cargo-audit clean after the lockfile bumps below.

## Findings
- **F1 (fixed, safe): 11 RustSec advisories** on first audit (quinn-proto x5, rustls x4, rustls-webpki, webpki-roots). Fixed with `cargo update -p` of those four crates (patch bumps in Cargo.lock only); full test run green after.
- **F2 (fixed): missing docs and broken rustdoc links** on core/kms public API (24 items) and 3 intra-doc links in api. Docs added; no behavior change.
- **F3 (DECISION): entropa-api does not meet the strict lints.** With the workspace set it has ~40 unwrap/expect and ~45 missing-docs warnings in library paths. It keeps only forbid(unsafe_code) and deny(dbg/todo/unimplemented) for now. Options: raise api to the strict set, or prune the product-demo code first (docs/PRUNE-PLAN.md), which removes most of it. Recommend prune first.
- **F4 (FIXED in S0d; was: ambiguous record encoding).** Original finding: `encode_record` joins payload and label with a NUL byte and does not reject NUL in the payload, so `("a\0b", None)` and `("a", Some("b\0"))` encode to identical bytes and therefore the same leaf hash. A signed log cannot tell those two records apart. Found by the decode_record fuzz target (crash input `[3,0,10]` in the round-trip assertion). Characterized by test `a_payload_containing_the_separator_decodes_as_payload_plus_label`. Fix would change leaf hashes: needs a versioned, length-prefixed encoding and a semver bump of entropa-core. Do NOT fix in S0b. Decide before S2/S3 write real records.
- **F5 (fixed, carried over from S0): checkpoint digest used `usize::to_be_bytes`**, 4 bytes on 32-bit targets. Now `(size as u64)`; golden layout test added (passed immediately on 64-bit: guard). `checkpoint()` now shares its parts with `checkpoint_with`.
- **F6 (tooling bug, fixed): mutants.sh gave flaky results** because parallel cargo-mutants jobs shared `CARGO_TARGET_DIR=/work/target`; one run reported "verify_consistency -> false" as MISSED, which is impossible. The script now unsets it. Lesson recorded: a surprising MISSED is a harness suspect first.
- **F7 (note): CI is untested on GitHub.** The workflow parses (PyYAML) and every `uses:` is SHA-pinned, but it has not run. The coverage and SBOM jobs rebuild the dev image each run (slow).
- **F8 (note): gitleaks is not in CI yet.** STANDARDS wants it; the Paxel guidance (public vectors look like secrets, document false positives in .gitleaks.toml) belongs to S0c.

## Could not verify
Anything needing GitHub itself (workflow execution, branch protection, CODEOWNERS enforcement); cargo-semver-checks (installed, not run: nothing published); 32-bit behavior of the digest (no 32-bit target in the image); individual tool versions are not pinned beyond `cargo install --locked`.

## Update 2026-10-20 (S0d)
F4 is fixed by record encoding v2 (docs/adr/0011-record-encoding-v2.md, entropa-core 0.2.0): injective, canonical, strict decoder, 1 MiB field limit. Red evidence: docs/evidence/s0d-red.txt; green: s0d-green.txt, s0d-check.txt; mutation on record.rs 33/33 caught (s0d-mutants.txt). Test count 278 passed, 0 failed, 4 ignored.
