# Entropa Gate

### Verify, don't trust. Free, open AI security and post-quantum audit trails, for public safety.

**Our mission.** AI systems are being trusted with decisions about people's money, health, work and safety, and almost no one outside the vendor can check what they did or why. We think that is dangerous. Entropa exists to make AI and LLM security, and tamper-evident, post-quantum-signed audit trails, free and open for everyone: tools that limit what an AI can read and send, and a signed record of every decision that anyone can verify for themselves, today and after quantum computers. We publish our results, including every failure, because public safety needs proof, not promises.

A post-quantum signed Merkle transparency log for the decisions of AI agents and people, with a default-deny egress guard in front of model calls, access tokens, tiers and change control around it, and a way for a reader to check all of it offline. Written in Rust.

**Status: a research prototype, published in full.** Nothing here has had an independent review. Every number below is our own measurement, or a re-run by a second reviewer, and failures are reported next to successes. Do not rely on it to protect real data.

- Results of the sealed and held-out runs, failures first: https://results.entropa.space (also in `docs/public/RESULTS.md`)
- Documentation, threat model and how to verify a ledger yourself: https://docs.entropa.space (also in `docs/public/`)
- What is not done, not tested or not decided: `docs/public/KNOWN-LIMITS.md`

## What is built
- **Ledger and verifier**: signed, append-only, hash-chained records with ML-DSA-65 signatures and Merkle checkpoints; an offline verifier; a witness that cosigns checkpoints (`crates/core`, `ledger`, `witness`, `nodecore`, `platinum`, `gate`).
- **Egress guard**: a rule engine that decides whether an outbound request may leave (`crates/egress`). A structural, typed-fields layer sits in front of a heuristic secret scanner.
- **Access tokens, tiers and change control** (`crates/tokens`, `tiers`) and a **retrieval service over a sealed corpus** of standards (`crates/standards`; the corpus text is NOT in this repository).
- **"Try the gate"**: a small HTTP service around the guard, its container image build and a sealed-scenario runner (`crates/try`, `try-http`).
- Release tooling and the scripts that produced the evidence under `docs/evidence`. (The website copy is not part of this repository.)

## What is measured, and where it fails (summary; the full tables are in `docs/public/RESULTS.md`)
- **Egress guard, sealed round 6: FAILED.** 468 of 1,042 secret-bearing requests leaked (44.9 percent); our forecast of 2 to 10 percent was wrong. Round 5 leaked 293 of 1,113. The guard is a heuristic with known misses and must not be used as a complete secret filter.
- **Retrieval, sealed round 3:** one of 24 planted-instruction cases was obeyed (the bar was none); description-only questions were answered correctly in 7 of 39.
- **"Try the gate" HTTP service, sealed round:** 442 of 448 scenarios passed; five of the six failures were flaws in the test set and one is a real minor gap (a request without a `Host` header is answered).
- Tokens and tiers: 2,090 attack scenarios in 13 classes; one real hole was found and fixed (a child token shown without its parent).
Each set is spent after one run and is never reused as a bar. The sealed sets themselves are not published.

## Building and testing
`cargo build --release --offline` and `cargo test --release --offline` from a clean clone (the toolchain is pinned in `rust-toolchain.toml`; dependencies must be available offline or fetched once). Some tests start local servers on the loopback interface. The admin UI crate needs its UI built first (`scripts/build-admin-ui.sh`).

## Third-party text
Short quotations of PCI DSS v4.0.1 requirement text identify the requirements mapped; copyright PCI SSC; no other third-party standards text is included.

## Contributing and security
Contributions are not open yet; see `CONTRIBUTING.md`. To report a security problem privately, use the contact form at https://entropa.space/contact; see `SECURITY.md`.

## Licence
**Apache-2.0** for the code and **CC-BY-4.0** for the documentation: a full giveaway. Use it, change it, sell it; keep the copyright notice; provided as is, no warranty, use at your own risk (Apache-2.0 sections 7 and 8). `entropa-core` and `entropa-node` were published earlier under MIT and stay MIT (`LICENSE-MIT`). The name "Entropa" is not licensed: forks must rename. Contributions (DCO sign-off, no CLA) open after the first full release; forks are welcome now (see `CONTRIBUTING.md`). The project is paid for by custom work: setup, architecture review, attack tests and training (https://entropa.space/contact).

## A note on older documents
`docs/` also holds historical documents from earlier designs of Entropa (a hosted billing service, an open-core split, an earlier consensus design). They are kept for the record and may describe things that no longer exist. The current documents are in `docs/public/` and at https://docs.entropa.space, and what is built, measured and failing today is at https://results.entropa.space.
