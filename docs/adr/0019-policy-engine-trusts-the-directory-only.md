# ADR 0019: a production build of entropa-policy only exposes the directory-bound engine

Status: accepted by the reviewer's order (S4d), 2026-10-21.

## Context
S4c added `Engine::with_directory`, so that a principal's role and key status come from the signed actor
directory. The S4b tests (unedited by rule) build engines with `Engine::new` and put `role` and `has_key` in the
`Request`. That constructor therefore trusts request fields. If a production caller forgets `with_directory`, a
request can claim `role: human` and the Cedar rule for hard-rule actions would be satisfied by a claim.

## Decision (a stated deviation from docs/ARCHITECTURE-CEDAR.md, which lives on branch rerust-s4a-cedar-arch)
- The design doc says the role is read from the signed actor directory; S4d makes the type system enforce it.
- `Engine::new` and `Engine::with_directory` (the request-trusting path) exist only with the cargo feature
  `trust-request-fields`, which is off by default.
- The always-available constructor is `Engine::new_bound(schema, policies, directory)`: role and key status come only
  from the directory, and an unknown principal is denied (`Reason::InvalidRequest`).
- The crate's own tests enable the feature through a dev-dependency on itself; the fuzz crate enables it explicitly.
  No S4b test file is edited.
- A static test (`tests/feature_guard.rs`) checks that the feature is not in `default`, and that no crate manifest
  other than the policy crate's own dev-dependency and its fuzz crate turns it on.

## Consequences
- A production build cannot construct a request-trusting engine; forgetting the directory is a compile error.
- `Request.role` and `Request.has_key` remain in the struct (the S4b tests need them) and are ignored by the bound engine.
- Cargo feature unification: any workspace member that enables the feature turns it on for every crate built in the
  same invocation, so the guard test also scans all manifests.
