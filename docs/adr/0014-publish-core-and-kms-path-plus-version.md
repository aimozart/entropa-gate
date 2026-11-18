# ADR 0014: publish entropa-core and entropa-kms; path plus version dependencies
Date: 2026-10-20. Status: accepted (stage S0e).

## Context
The owner wants the crates he already has Trusted Publishing for on crates.io used as the home of this code. entropa-core 0.1.3 is published; entropa-kms is new. entropa-api (the service layer) must stay unpublished.

## Decision
- entropa-core and entropa-kms are publishable: full metadata (description, repository, homepage, documentation, readme, keywords, categories, rust-version = 1.99, the version we test), an `include` list that packages sources, tests with their small public vectors and examples but not fuzz corpora, evidence or proptest seeds, and a LICENSE-MIT copy in each crate.
- Workspace-internal dependencies use `{ path = "../core", version = "0.2.0" }`: the path is used in development, the version when published. Future crates follow the same pattern. entropa-api keeps `publish = false`.
- Releases go out only through the tag-triggered Trusted Publishing workflow (.github/workflows/release.yml), never from a developer machine with a stored token.
- Unused dependencies were removed from entropa-core before publishing (`reqwest`, `sha3` were not referenced by any source or test); `serde_json` moved to dev-dependencies.

## Consequences
0.2.0 is a major break from the published 0.1.3: the old `chain`, `block` and `beacon` modules are gone (docs/evidence/s0e-semver-checks-forced.txt). Consumers on 0.1.x are unaffected until they upgrade. rust-version states 1.99 because that is the only compiler we test; lowering it needs a CI job on the older toolchain first.
