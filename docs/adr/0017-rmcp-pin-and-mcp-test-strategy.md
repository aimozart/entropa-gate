# ADR 0017: pin rmcp 3.6.0 for the MCP server; red-test strategy for S2b
Date: 2026-10-20. Status: accepted (stage S2b; D4 of docs/ARCHITECTURE-MCP.md).

## Decision
- The MCP server (S2c) uses `rmcp = "=3.6.0"` with `default-features = false, features = ["server", "macros", "transport-io"]`, plus `tokio` (`rt`, `macros`, `io-util`) and `serde`. Smoke test run on 2026-10-20 in a scratch crate (not committed; output in docs/evidence/s2b-rmcp-smoke.txt): a one-tool stdio server built with `#[tool_router]`/`#[tool_handler]` compiles, answers the legacy `initialize` (protocol 2025-11-25, `capabilities.tools`), `tools/list` shows `inputSchema` and `outputSchema` (JSON Schema 2020-12), and `tools/call` returns a text block plus `structuredContent` with `isError: false`. Not yet exercised with 3.6.0: the modern `server/discover` path and cancellation (left to the S2c protocol tests P3/P6).
- rmcp is NOT added in S2b: the stub crate has no rmcp dependency, so the red tests fail only for "not yet implemented", not for SDK reasons. It is added in S2c with this pin.
- S2b structure: `entropa-mcp` is a library (the pure core: `Server::call_at`, `Config`, `FileSource`, `key_id`) plus a binary. The core is tested directly with an injected clock (rate limiter) and an in-memory `LogSource`; the protocol rows run the real binary over stdio with a hand-written JSON-RPC client. Every stub answers `not yet implemented`; test helpers turn that answer into the failure message, so each red test names its reason.

## S2c findings (2026-10-20)
- rmcp 3.6.0 answers a malformed `tools/call` (missing `name`, `arguments` not an object, missing params) with JSON-RPC error `-32601` ("tools/call"), not `-32602`; an unknown tool name gets `-32602` as the spec example shows. The protocol test P4 now accepts either code for the malformed cases and requires "error, no result". Which code the spec requires for a malformed request is UNVERIFIED (the Tools page names `-32602` only for the unknown tool).
- The S2a draft limit of 8 KiB for `explain_proof` was infeasible (66 steps of full hashes); the limit and test E4 became 24 KiB.

## Consequences
49 contract tests exist before any behavior: 47 red, 2 static guards (no write paths, no cloud/HTTP dependencies) that pass and must keep passing. S2c makes them green without weakening them.
