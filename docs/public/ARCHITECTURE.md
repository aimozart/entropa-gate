# Architecture

A short map of the parts. Each part is a separate crate in this repository.

## The log

- Records are appended to a Merkle log; after each append a checkpoint (the tree size and root) is signed with ML-DSA-65, a post-quantum signature scheme. [evidence: crates/core/src/merkle.rs, crates/core/src/pqc.rs, crates/core/src/transparency_log/checkpoint.rs]
- A reader can ask for a receipt (an inclusion proof) for a record and for a consistency proof between two checkpoints. [evidence: crates/core/src/transparency_log/mod.rs, crates/core/src/transparency_log/batch_receipt.rs]
- Events written to the log use a closed vocabulary: kinds, labels, decisions and reasons are fixed lists, and free text is hashed and dropped rather than stored. [evidence: crates/ledger/src/vocab.rs, crates/ledger/src/platinum.rs]
- One network-free implementation validates a request, signs it and appends it with a signed checkpoint, and another verifies a whole ledger offline; the node and the client program share it. It was introduced with byte-for-byte pins taken from the older code. [evidence: crates/nodecore/src/lib.rs, a stage record (not published)]
- A ledger can be opened for reading without writing anything (no lock file, no directory created), so it can be verified on read-only media or while a writer is running. [evidence: crates/ledger/src/store.rs, a stage record (not published)]

## The gate in front of a model

- Capability tokens signed with ML-DSA-65 limit what a caller may do: tier, action scope, corpus, spend and rate limits, and delegation to child tokens. [evidence: crates/tokens/src/lib.rs, a stage record (not published)]
- Every decision of the gate is recorded as a signed, data-minimal ledger record (hashes and closed codes). [evidence: crates/tiers/src/lib.rs, a stage record (not published)]
- An egress guard inspects what would leave toward a model (destinations, blocked terms, personal-identifier shapes, secret shapes, malformed input) and allows, redacts or blocks it by tier. It is a heuristic scanner, and its measured misses are on the results page. [evidence: crates/egress/src/lib.rs, docs/results/results.json]
- A policy engine (Cedar) answers allow or deny for the actions the tokens name. [evidence: crates/tiers/src/cedar.rs, a stage record (not published)]

## Showing the ledger

- A static explorer bundle is generated from a mock ledger after the ledger has been verified; it carries the label "mock data, real signed records" on every page and file, and shows only closed codes and hashes. [evidence: crates/mockview/src/lib.rs, a stage record (not published)]
- The bundle can include a tar of the ledger so a reader can check it with their own copy of the verify program. [evidence: docs/evidence/ls2/]

## Releasing

- A release is described by a manifest (hashes of every file plus the hash of a software bill of materials built from the lock file), signed with ML-DSA-65, with a command-line tool to create the key, build the bill of materials, sign and verify. [evidence: crates/release/src/lib.rs, a stage record (not published)]
- Two builds in two fresh containers produced identical bytes on one host. [evidence: docs/evidence/s2/]
