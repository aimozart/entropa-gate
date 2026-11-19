# Engineering standards (industry best practice, original checklist; the owner 2026-10-20: "super best practices")
Every stage is held to this. A stage is not done until its relevant lines here are green or explicitly waived by the owner with a reason in the decision records.
## Code and design
- Rust edition and toolchain pinned (rust-toolchain.toml); workspace lints in Cargo.toml: forbid unsafe_code, deny missing_docs on public APIs, clippy -D warnings (plus a chosen pedantic subset), rustfmt enforced.
- Small crates with one job; files under ~500 lines; errors via thiserror with typed variants; no unwrap/expect in library paths (tests excepted); no panics on untrusted input.
- Architecture Decision Records in docs/adr/ (context, decision, consequences); public API documented with doctests; semver discipline with cargo-semver-checks for published crates.
## Testing pyramid (every behavior test-first, red then green)
- Unit + integration tests; known-answer vectors (ML-DSA, Merkle, and the captured AWS KMS vector); property tests (proptest) for Merkle proofs and signers; fuzz targets (cargo-fuzz) for every parser/deserializer; mutation testing (cargo-mutants) with a minimum kill rate; coverage with cargo-llvm-cov and a floor; snapshot tests where output is a contract; deterministic seeds recorded.
- Benchmarks (criterion) for hot paths (append, root, receipt, verify, sign) with a committed baseline; no performance claim without numbers.
## Supply chain and security
- Cargo.lock committed; cargo build --locked in CI; cargo-deny (advisories, licenses, bans, sources) and cargo-audit in CI; dependabot/renovate; minimal dependencies, each justified in an ADR when added.
- SBOM (CycloneDX) generated and attached to releases; build provenance/attestation for release artifacts; container images built from pinned digests and scanned; secret scanning (gitleaks) in CI and as a pre-push gate; signed commits/tags where possible.
- Threat model in docs/THREAT-MODEL.md (STRIDE per component: log, sequencer, signer, MCP server, approval gate, witness); security.txt and SECURITY.md; least-privilege cloud roles; OIDC for CI to clouds (no long-lived keys); keys only in KMS/HSM for production signing.
## Delivery and operations
- CI on every push: fmt, clippy, test (all features), doc, deny, audit, coverage, mutation (nightly), fuzz smoke; branch protection and required reviews on GitHub when public; conventional commits and a generated changelog; reproducible container builds with --locked.
- Observability: structured logs (never secrets), tracing with OpenTelemetry-compatible spans, health and readiness endpoints, SLOs and an error budget, runbooks in docs/runbooks/, a load/soak test with recorded results.
- FinOps: every cloud resource priced first in the cost notes, tagged project=entropa, with a teardown command; unit cost per request tracked; nothing left running.
## AI-assisted development governance (our differentiator)
- AI-written code is attributed (Co-Authored-By trailer), reviewed by the reviewer, and every stage records evidence (commands and outputs) in AI-LOG and DECISION_OUTCOMES; humans gate approvals; Paxel report per repo (--project entropa-rust) after meaningful stages; prompts stored in docs/prompts/.
## Red-phase checklist (added 2026-10-21 after S12b/S12c)
For every new test, before it counts as red: (1) it fails for the stated reason (not a harness error, not a stub's panic message you never read); (2) **it is run against a deliberately broken or loosened implementation of the exact behaviour it claims to check and must fail there too** (mutation by hand; a test that cannot fail checks nothing); (3) the helper that builds its input does not alter the field under test (no payload builder that overwrites the value being tested); (4) the expected value is derived independently of the code under test (a separate generator, hand arithmetic, or a published vector); (5) the evidence line (command and output) is saved in docs/evidence/.

