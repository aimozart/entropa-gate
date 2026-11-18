# ADR 0018: cedar-policy 4.14.0 as the policy engine
Date: 2026-10-21. Status: accepted by the reviewer (D10, stage S4a); first used in S4b.

## Context
S4 needs a default-deny policy gate where a `forbid` always wins (docs/ARCHITECTURE-CEDAR.md). Cedar is the language AWS built for this and is what Amazon Bedrock AgentCore Policy evaluates, so using the same engine keeps the local design and the SAP-C03 mapping honest.

## Decision
Depend on the `cedar-policy` crate, pinned `=4.14.0` (Apache-2.0, rust-version 1.89; the workspace toolchain is 1.99.1), in the new crate `entropa-policy` only. No other crate gains it. Policy and schema text are loaded from strings; the crate does no I/O, networking or process spawning (static guard test N1).

## Consequences: what it adds (from the Cargo.lock diff, 2026-10-21)
- **78 lock entries**, of which these crates are new to the workspace: aho-corasick, ar_archive_writer, arrayvec (second version), ascii-canvas, bit-set, bit-vec, bs58, cedar-policy, cedar-policy-core, cedar-policy-formatter, defmt (+ macros, parser), educe, ena, enum-ordinalize (+ derive), fixedbitset, jiff (+ core, static, tzdb, tzdb-platform), keccak, lalrpop, lalrpop-util, linked-hash-map, linked_hash_set, lock_api, logos (+ codegen, derive), miette (+ derive), new_debug_unreachable, nonempty, parking_lot (+ core), petgraph, phf_shared, pico-args, portable-atomic (+ util), precomputed-hash, pretty, psm, redox_syscall, regex, regex-automata, rustc-literal-escaper, same-file, schemars, scopeguard, serde_with (+ macros), sha3, siphasher, smol_str, stacker, string_cache, term, typed-arena, unicode-normalization, unicode-script, unicode-security, unicode-width, unicode-xid, walkdir, winapi-util; plus second versions of base64, hashbrown, indexmap, bitflags and itertools. Most are build-time parser generators (lalrpop, logos) and diagnostics (miette).
- Checks run on 2026-10-21 with the dependency in the tree: `cargo deny check` reports advisories, bans, licences and sources ok (only duplicate-version warnings: arrayvec, cpufeatures, crypto-common, digest, getrandom, itertools, keccak, rand_core, syn, unicode-width, windows-sys); `cargo audit` scans 384 crates and reports no vulnerability.
- Build time and binary size grow; only entropa-policy and anything that depends on it pay for it.
- Cedar skips a policy that errors during evaluation (documented behaviour); the engine therefore treats any error diagnostic as Deny (D4).
- Dogwood (the Cedar superset AgentCore uses for temporal policies) is not used (D9).
