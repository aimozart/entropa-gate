# ARCHITECTURE-MCP: Entropa read-only log inspection server (`entropa-mcp`)

Status: **design only, no code** (stage S2a, 2026-10-20). A proposal for the reviewer and the owner to audit. Modelled on `../clinic-ops/docs/ARCHITECTURE-MCP.md` (read, not copied). Anything not confirmed is marked **UNVERIFIED** and collected in section 13; open decisions are in section 14.


## 1. Purpose and shape
`entropa-mcp` is a Model Context Protocol server that lets an AI client **inspect and verify** the Entropa transparency log. It answers "what is the log head?", "is this checkpoint signed by a key I trust?", "is this record really in the log?", "what are the latest records?", and "explain this inclusion proof step by step". It **cannot change anything**.

- Language: Rust, new crate `crates/mcp` (package `entropa-mcp`), depending on `entropa-core` only (no `entropa-api`, no `entropa-kms`, no AWS crate).
- SDK: `rmcp` (the official Rust SDK). Version pinned after a compile smoke test in S2b/S2c (D4).
- Transport: **stdio only**. No HTTP listener, no port.
- Tools: exactly five, all read-only: `log_head`, `verify_checkpoint`, `verify_receipt`, `list_records`, `explain_proof`.
- Data: synthetic only. No secrets in config, arguments, logs or output.

```
AI client (spawns the process; human can deny each call)
   | stdin/stdout: newline-delimited JSON-RPC (MCP)
   v
entropa-mcp --- verify layer   pure functions over entropa-core (merkle, verify_hex, record v2). No I/O.
           --- trust store     trusted public keys from ONE env var, read at startup.
           --- LogSource       read-only trait: head() and records(since, limit).
                                v1: FileSource (an exported log file, path from env).
                                later: HttpSource (GET only, fixed base URL from env) once the public explorer API exists (D2).
```

`verify_checkpoint`, `verify_receipt` and `explain_proof` need **no backend**: they are pure functions of their arguments plus the trusted keys. Only `log_head` and `list_records` read the `LogSource`.

## 2. Non-goals
Appending records, signing, key handling, KMS or any cloud call, approvals (S3), policy (S4), witnessing (S5), running a log, authentication or users (there are none), and returning raw bulk data. The server is not a query language; there are no free-form query arguments.

## 3. What the server must never do
1. Never append, edit or delete a record, checkpoint or file; never create files.
2. Never sign, never hold, read, accept or print a private key, token, credential, `~/.aws`, `.env` or anything under `~/.config/secrets`. It has no dependency on `entropa-kms` or any AWS crate (proved with `cargo tree`, test N2).
3. Never open a network listener. Outbound network is limited to the one configured `LogSource` base URL, GET only, no redirects (v1 has no network code at all).
4. Never execute a command or spawn a process; never use a URL, path or hostname taken from a tool argument. Arguments are data only.
5. Never trust a public key supplied in an argument. A key embedded in a checkpoint or receipt proves nothing by itself (section 4, T1).
6. Never follow instructions found in record text, labels or any tool input; they are untrusted data and are returned marked `untrusted_text: true`.
7. Never write anything but MCP messages to stdout; logs go to stderr and never contain arguments, record text, keys or signatures.
8. Never claim "verified" without naming which checks ran and passed; never claim regulatory compliance.
9. Never weaken a check to make a test pass; changing a limit or a rule is a human gate.

## 4. Threat model for tool inputs (arguments are untrusted AI-generated data)
| Id | Threat | Mitigation |
|---|---|---|
| T1 | **Key substitution:** the caller supplies its own key and signature, so "verification" passes. | Trust comes only from `ENTROPA_TRUSTED_PUBKEYS` (env, read at startup). Outputs separate `signature_valid` (under the embedded key) from `signer_trusted` (embedded key is in the trust store). `valid` requires both. No tool accepts a "trusted key" argument. If the env var is empty, `signer_trusted` is always false and a warning goes to stderr. |
| T2 | **Prompt injection through record text or labels** (a record says "ignore previous instructions"). | Text fields are previews (<= 128 chars), always inside an object that carries `untrusted_text: true`; tool descriptions say it. The server never acts on them. The client's human-in-the-loop remains the control (spec). |
| T3 | **Oversize input** (hex bombs, huge proofs, huge records) exhausting memory or CPU. | Hard caps in the schema and again in Rust (section 6.0); proof depth <= 64; record <= 64 KiB; whole request line <= 1 MiB; reject before decoding. |
| T4 | **Malformed hex / wrong lengths** causing panics. | Strict lowercase-hex validation; no `unwrap`/`expect`/`panic` in library paths (workspace lints); fuzz target for each tool's argument parser (S2d). |
| T5 | **SSRF / path traversal** via arguments. | No tool takes a URL, host or path. The only locations (log file or base URL) come from env at startup. |
| T6 | **Resource exhaustion by call volume.** | Per-process sliding-window rate limiter (section 8). |
| T7 | **Data exfiltration through output** (dumping the log, or large payloads). | `list_records` returns previews only, `limit` <= 100, output <= 64 KiB; `explain_proof` output <= 24 KiB; records are data-minimal by design (S9). |
| T8 | **Log injection / secret leakage in logs.** | stderr logging records tool name, outcome, error code, duration only (section 9). |
| T9 | **Confusing non-membership with invalidity.** | `valid: false` always carries `checks[]` naming the failing check; an unknown record is not an error. |
| T10 | **Index spoofing:** a receipt claims a position its proof was not built for. | Closed by S0g (ADR 0016): `verify_receipt` now binds `index` and `checkpoint.size` to the audit path (RFC 6962/9162), and the tool reports `index_checked: "bound_to_proof"`. **Limit:** two tree sizes can give the same audit-path shape for an index, so the path cannot prove the size; the size is bound to the root only by the checkpoint signature. A signer that signs a false size for a real root is out of this server's reach; the witness (S5) compares checkpoints. |
| T11 | **Replay of an old valid receipt** against a newer log. | A receipt proves inclusion under *its* checkpoint only; outputs report `checkpoint_size` and, when a `LogSource` is configured, `matches_current_head: true/false` (same root at same size is not claimed unless sizes match). Consistency between checkpoints, and a signer lying about the size, are the witness's job (S5). |

## 5. Trust boundaries and configuration
- **Boundary A (client to server):** untrusted arguments. Everything validated (JSON Schema and again in Rust).
- **Boundary B (server to log data):** the `LogSource` content is untrusted until verified: `log_head` verifies the checkpoint signature against the trust store before reporting `signer_trusted`.
- **Boundary C (server to host):** none: no files written, no processes, stdout only MCP.
- Configuration is environment variables only, read once at startup, none secret: `ENTROPA_TRUSTED_PUBKEYS` (comma-separated lowercase hex ML-DSA-65 public keys, 3904 chars each, at most 8), `ENTROPA_LOG_FILE` (path of an exported log, v1) or later `ENTROPA_LOG_URL`. The config struct has no token, key or password field (test N3).
- Key id: the first 16 hex chars of BLAKE3 over the public key bytes, shown as `key_id`. Data-minimal: the full key is never echoed back except where the caller supplied it.

## 6. Tools
Common rules: tool names use only `A-Za-z0-9_` (spec SHOULD). Tools are listed in this fixed order. Every result carries `structuredContent` conforming to a declared `outputSchema` plus the same JSON as a text block (spec: SHOULD). Annotations (`readOnlyHint: true`) are included but are untrusted hints for clients; the guarantee is the server code (section 3). All outputs are JSON objects.

### 6.0 Shared types and limits
- `hex`: string, pattern `^[0-9a-f]*$`, even length, lowercase only (uppercase is `invalid_arguments`).
- `hash`: `hex` of exactly 64 chars. `pubkey_hex`: `hex`, `maxLength` 3904. `signature_hex`: `hex`, `maxLength` 6618 (ML-DSA-65: 1952-byte key, 3309-byte signature). Well-formed hex of the wrong length is **not** an argument error: the tool answers `signature_valid: false` with a reason.
- `checkpoint`: `{ root: hash, size: integer 0..2^53-1, timestamp: integer 0..2^53-1, proposer_pubkey: pubkey_hex, signature: signature_hex }` (matches `entropa_core::transparency_log::Checkpoint`; `additionalProperties: false`).
- `receipt`: `{ index: integer 0..2^53-1, record: hex (<= 131072 chars = 64 KiB), proof: array (<= 64) of { sibling: hash, side: "Left" | "Right" }, checkpoint }` (matches `Receipt` and `ProofStep`; `additionalProperties: false`). Records above 64 KiB are rejected even though format v2 allows ~2 MiB (D5).
- Record preview: `{ decode_ok: bool, payload_preview: string (<= 128 chars), payload_truncated: bool, label_preview: string|null, record_format_version: 2, untrusted_text: true }`; `decode_ok: false` (strict v2 decoder rejected the bytes) shows empty previews.

### 6.1 `log_head`
Reports the newest checkpoint known to the `LogSource`.
- **Input** `{}` (`additionalProperties: false`).
- **Output** `{ size, root, timestamp, signer_key_id, signature_valid: bool, signer_trusted: bool, record_format_version: 2, source: "file"|"http", source_as_of: string|null }`.
- **Example** call `{"name":"log_head","arguments":{}}`; result `{"size":3,"root":"9f2c...(64 hex)","timestamp":1700000000,"signer_key_id":"a41c0d9e55b2f700","signature_valid":true,"signer_trusted":true,"record_format_version":2,"source":"file","source_as_of":null}`.
- **Errors** no `LogSource` configured or unreadable: `isError: true`, `{"error":"unavailable","detail":"log source not reachable"}` (no paths in `detail`). A head whose signature fails is a normal result with `signature_valid: false`.

### 6.2 `verify_checkpoint`
Checks one checkpoint's signature and whether the signer is trusted.
- **Input** `{ checkpoint }` (section 6.0).
- **Output** `{ signature_valid, signer_trusted, claimed_key_id, trusted_key_id: string|null, size, root, digest_layout: "root(32)||size(u64be)||timestamp(u64be)", checks: [ { name, passed, detail } ] }`. `checks` names `signature_under_embedded_key`, `signer_in_trust_store`.
- **Example** call `{"name":"verify_checkpoint","arguments":{"checkpoint":{"root":"<64 hex>","size":3,"timestamp":1700000000,"proposer_pubkey":"<3904 hex>","signature":"<6618 hex>"}}}`; result `{"signature_valid":true,"signer_trusted":true,"claimed_key_id":"a41c0d9e55b2f700","trusted_key_id":"a41c0d9e55b2f700","size":3,...}`. A tampered root gives `signature_valid:false` and a `checks` entry `signature_under_embedded_key: passed false`.
- **Errors** non-hex, uppercase, over-cap, missing/extra/mistyped fields: `invalid_arguments`.

### 6.3 `verify_receipt`
Checks a receipt end to end: checkpoint signature, signer trust, and Merkle inclusion of the record.
- **Input** `{ receipt }` (section 6.0).
- **Output** `{ valid, signature_valid, signer_trusted, inclusion_valid, index_checked: "bound_to_proof", index, checkpoint_size, leaf_hash, record: <record preview>, matches_current_head: bool|null, checks: [ { name, passed, detail } ] }`. `valid = signature_valid && signer_trusted && inclusion_valid && index < checkpoint_size`. `matches_current_head` is `null` when no `LogSource` is configured.
- **Example** call `{"name":"verify_receipt","arguments":{"receipt":{"index":1,"record":"020000000368697400","proof":[{"sibling":"<64 hex>","side":"Left"}],"checkpoint":{...}}}}`; result `{"valid":true,"signature_valid":true,"signer_trusted":true,"inclusion_valid":true,"index_checked":"bound_to_proof","index":1,"checkpoint_size":2,"leaf_hash":"...","record":{"decode_ok":true,"payload_preview":"hit","payload_truncated":false,"label_preview":null,"record_format_version":2,"untrusted_text":true},"matches_current_head":null,"checks":[...]}`. (The record hex is format v2 for payload "hit" with no label: `02 00000003 686974 00`; the other hashes are placeholders.)
- **Semantics** `valid: false` is a normal result, never an error; `checks` says which check failed (T9). A receipt valid under an untrusted key returns `valid:false, signature_valid:true, signer_trusted:false`.
- **Description text must say:** a valid receipt proves who recorded what and that it was not changed; it does not prove the AI decision was correct, the index and tree size are bound to the proof path, but the tree size is bound to the root only by the checkpoint signature (T10).

### 6.4 `list_records`
Lists recorded entries from the `LogSource`, previews only.
- **Input** `{ limit?: integer 1..100 (default 20), since_index?: integer >= 0 }` (`additionalProperties: false`).
- **Output** `{ records: [ { index, leaf_hash, record_len, preview: <record preview> } ], total: integer, next_since_index: integer|null }`. Oldest first; `since_index` keeps entries at or above it; `total` is the log size at the head the source reported; the listing is taken against that head.
- **Example** call `{"name":"list_records","arguments":{"limit":2,"since_index":0}}`; result `{"records":[{"index":0,"leaf_hash":"...","record_len":23,"preview":{...}},{"index":1,...}],"total":3,"next_since_index":2}`.
- **Errors** `limit` 0 or 101, negative or non-integer `since_index`, unknown fields: `invalid_arguments` (never silently clamped). `since_index >= total` returns an empty list, not an error. No source: `unavailable`.
- Cannot return full payloads beyond 128 chars, and cannot be paged faster than the rate limit.

### 6.5 `explain_proof`
A human-readable walk through an inclusion proof, computed locally (no backend).
- **Input** `{ receipt }` (same as `verify_receipt`).
- **Output** `{ steps: [ { n, operation: "leaf_hash"|"combine"|"compare", formula, side?, inputs: [hash...], output: hash } ], root_matches: bool, signature_checked: false, narrative: string (<= 4000 chars) }`. Step 1 is `BLAKE3(0x00 || record_bytes)`; each `combine` is `BLAKE3(0x01 || left || right)` with the sibling on the stated side; the last step compares with `checkpoint.root`. `signature_checked: false` is explicit: this tool explains the Merkle path only; use `verify_receipt` for trust.
- **Example** call `{"name":"explain_proof","arguments":{"receipt":{...}}}`; result `{"steps":[{"n":1,"operation":"leaf_hash","formula":"BLAKE3(0x00 || record_bytes)","inputs":[],"output":"..."},{"n":2,"operation":"combine","side":"Left","formula":"BLAKE3(0x01 || sibling || current)","inputs":["<sibling>","<current>"],"output":"..."},{"n":3,"operation":"compare","formula":"computed root == checkpoint.root","inputs":["...","..."],"output":"..."}],"root_matches":true,"signature_checked":false,"narrative":"..."}`.
- **Errors** same argument rules as `verify_receipt`; a proof that does not reach the root is a normal result with `root_matches:false` and the narrative saying where the computed root differs.

## 7. Error contract
Follows the 2026-07-28 Tools page: **protocol errors** (JSON-RPC, e.g. `-32602`) for an unknown tool or a request that fails the `CallToolRequest` schema; **tool execution errors** (`isError: true`) for input validation errors, backend failures and business-logic results the model can act on. Mapping:
| Situation | Kind | Body |
|---|---|---|
| Unknown tool; no `name`; `arguments` not an object | protocol error `-32602` | standard JSON-RPC error |
| Bad arguments (non-hex, uppercase, over cap, missing/extra/mistyped field, `limit` out of range) | tool execution error | `{"error":"invalid_arguments","detail":"<what is wrong and what is expected>"}` (detail cut to 600 chars; never echoes the offending value) |
| Log source missing or unreadable | tool execution error | `{"error":"unavailable","detail":"log source not reachable"}` |
| Rate limit exceeded | tool execution error | `{"error":"rate_limited","limit":"overall"|"list_records","retry_after_seconds":N,"detail":"..."}` |
| Verification failed (bad signature, untrusted key, proof mismatch, unknown record) | **normal result** (`isError:false`) | the tool's output with `valid:false` and `checks[]` |
No stack traces or file paths in any body.

## 8. Rate and size limits
- 30 tool calls per minute overall; 10 per minute for `list_records`. Sliding window per process; invalid calls count; refused calls are not recorded; unknown tools are not counted. Clock injected so tests never sleep.
- Request line <= 1 MiB, enforced at the stdio edge by a bounded line pump (S2d): an over-long line is dropped without buffering it and answered with a protocol error naming `entropa/request_too_large`; strings and arrays capped as in 6.0; tool output <= 64 KiB (`list_records`), 24 KiB (`explain_proof`; was 8 KiB in the S2a draft, which cannot hold 66 steps of full 64-hex hashes, changed in S2c), 4 KiB (others).
- Source response cap (later HttpSource): 1 MiB, 2 s connect, 5 s read (proposals, UNVERIFIED under load).

## 9. Logging
stderr only, one JSON object per tool call: `{ts, tool, outcome: "ok"|"invalid_arguments"|"unavailable"|"rate_limited", valid?: bool, ms}`. Never arguments, record text, keys, signatures or hashes. A startup line states the number of trusted keys (not the keys) and the source kind. stdout carries only MCP messages (spec MUST; test P5).

## 10. Protocol requirements (spec 2026-07-28; checked 2026-10-20)
- Capabilities: `tools` only, `listChanged` false; no resources, prompts, sampling, roots or elicitation; the server never asks the client for input.
- Servers MUST validate all tool inputs, implement access controls, rate limit and sanitise outputs; this design does so in sections 4, 6, 8.
- `tools/list` returns the five tools in the fixed order above, the same for every connection.
- Exit promptly on stdin EOF; stop work on `notifications/cancelled` (all tools are fast, pure or single read).
- Handshake: the 2026-07-28 revision has no `initialize` and carries `_meta` per request, with `server/discover`; legacy clients use `initialize`. Handled by `rmcp`; the S2b tests exercise both (how `rmcp` does it is UNVERIFIED here, see section 13).

## 11. Versioning
Server semver in `serverInfo`. Tool schemas are append-only within a minor version (new optional fields, new output fields). A breaking change to a tool adds a new tool name (`verify_receipt_v2`) and keeps the old one for a deprecation period. The record format version the server understands (`record_format_version: 2`) is reported in outputs; a future record format needs a new decoder and a minor version bump.

## 12. Test plan (implemented in S2b as red tests "not yet implemented", made green in S2c, hardened in S2d)
Notation: cases run through the real binary over stdio unless marked "unit". Fixtures: logs built in tests with `Probe::spawn()` (synthetic data only) and the public golden vectors.

| Id | Tool | Case | Expected |
|---|---|---|---|
| P1 | protocol | `tools/list` | exactly the 5 tools, in the order of section 6, names match `^[A-Za-z0-9_]+$`, each has `inputSchema` and `outputSchema` |
| P2 | protocol | legacy `initialize` then `tools/list` | success, capabilities `{tools:{}}` |
| P3 | protocol | modern `server/discover` and a request with `_meta` | success |
| P4 | protocol | unknown tool name; `tools/call` without `name`; `arguments` is an array | unknown tool: `-32602`; the malformed calls: a JSON-RPC error and no result (rmcp 3.6.0 answers `-32601`, so `-32601` or `-32602` is accepted; changed in S2c) |
| P5 | protocol | full session including errors | every stdout line is valid JSON-RPC; nothing else |
| P6 | protocol | close stdin | process exits promptly |
| P7 | protocol | responses may arrive out of order | test client matches by `id` |
| P8 | protocol | each result has `structuredContent` conforming to `outputSchema` and a text block with the same JSON | pass |
| H1 | log_head | file source with a trusted signer | `signature_valid` and `signer_trusted` true, size/root match the file |
| H2 | log_head | head signed by an untrusted key | `signature_valid` true, `signer_trusted` false |
| H3 | log_head | head with a tampered root | `signature_valid` false |
| H4 | log_head | no source configured / unreadable file | `unavailable`, no path in `detail` |
| H5 | log_head | extra argument | `invalid_arguments` |
| C1 | verify_checkpoint | valid checkpoint, trusted key | both true, `claimed_key_id == trusted_key_id` |
| C2 | verify_checkpoint | tamper each of root, size, timestamp (one at a time) | `signature_valid` false for each |
| C3 | verify_checkpoint | valid signature, key not in trust store | `signer_trusted` false |
| C4 | verify_checkpoint | empty `ENTROPA_TRUSTED_PUBKEYS` | `signer_trusted` false always; stderr warning |
| C5 | verify_checkpoint | signature of another key / wrong-length signature (well-formed hex) | `signature_valid` false, not an argument error |
| C6 | verify_checkpoint | non-hex, uppercase hex, odd length, over-cap length, missing/extra field, size as string, negative size | `invalid_arguments` |
| C7 | verify_checkpoint | empty-log checkpoint (size 0) | verifies |
| R1 | verify_receipt | valid receipt for each index of logs of size 1..10, trusted key | `valid` true |
| R2 | verify_receipt | tamper record, one proof sibling, a side flag, the checkpoint root, the signature (each) | `valid` false with the right failing `checks` entry |
| R3 | verify_receipt | valid receipt under an untrusted key | `valid` false, `signature_valid` true, `signer_trusted` false |
| R4 | verify_receipt | `index` >= `checkpoint.size` | `valid` false (index bound to the proof, S0g) |
| R5 | verify_receipt | record bytes that are not valid v2 | `record.decode_ok` false, previews empty, inclusion still evaluated |
| R6 | verify_receipt | record containing prompt-injection text | returned only as a <= 128-char preview inside `untrusted_text: true` |
| R7 | verify_receipt | F4 pair: record for `("a\0b", None)` presented with the proof of `("a", Some("b\0"))` | `inclusion_valid` false (distinct leaf hashes) |
| R8 | verify_receipt | proof of 64 steps ok, 65 steps, record of 64 KiB ok and 64 KiB + 1 | 65 steps and oversize record are `invalid_arguments` |
| R9 | verify_receipt | receipt matches current head / is older / newer than head | `matches_current_head` true / false / false; null with no source |
| L1 | list_records | default limit on a 5-record log | 5 records oldest first, `total` 5, `next_since_index` null |
| L2 | list_records | `limit` 2, then page with `next_since_index` | disjoint pages covering all records |
| L3 | list_records | `limit` 0, 101, -1, 1.5, "3"; `since_index` -1 | `invalid_arguments` |
| L4 | list_records | `since_index` >= total | empty list, no error |
| L5 | list_records | 10 KB payload record | preview <= 128 chars, `payload_truncated` true; total output <= 64 KiB |
| L6 | list_records | no source | `unavailable` |
| E1 | explain_proof | valid receipt, sizes 1..10 | steps = 1 leaf + proof length + 1 compare; `root_matches` true; hashes equal a local recomputation |
| E2 | explain_proof | tampered sibling | `root_matches` false, narrative names the mismatch |
| E3 | explain_proof | any input | `signature_checked` false always |
| E4 | explain_proof | output size with a 64-step proof | <= 24 KiB (changed from 8 KiB in S2c) |
| X1 | all | argument containing a URL, a path (`../../etc/passwd`), a shell string, an SSN-shaped string | treated as data; no network, no file read, no process; plain `invalid_arguments` or a verification result |
| X2 | all | request line > 1 MiB, deeply nested JSON (10,000 levels), NUL bytes, invalid UTF-8 | rejected without panic or hang |
| X3 | all | 1,000 random garbage argument objects per tool (proptest) | never panics; always a well-formed result or error |
| Q1 | rate | 31 calls in a window | 31st is `rate_limited` with `retry_after_seconds` >= 1 |
| Q2 | rate | 11 `list_records` calls | 11th `rate_limited` with `limit: "list_records"` |
| Q3 | rate | fake clock advanced 60 s | admitted again; refused calls did not extend the wait |
| N1 | static | source scan of the crate | no file write, no process spawn, no `println!`, no `unsafe`, no network call outside the optional `HttpSource` |
| N2 | static | `cargo tree -p entropa-mcp` | no `entropa-kms`, no `aws-*`, no `reqwest` in v1 |
| N3 | static | the config struct | only trusted keys and a log location; no token/key/password field |
| N4 | static | tool descriptions | contain the "does not prove the decision was correct" and "bound to the proof ... signature" statements |
| F1 | fuzz (S2d) | one libFuzzer target per tool's argument parser | no panic, bounded memory |
| M1 | mutation (S2e) | cargo-mutants on the crate | kill rate reported; survivors get tests |
| G1 | real client (S2f) | Claude Code via `.mcp.json`: allow / deny / error paths | recorded in `docs/REAL-CLIENT-TEST.md` |

## 13. Documentation used, and what could not be verified
Fetched and read on 2026-10-20 (WebFetch):
- MCP spec 2026-07-28, Tools: https://modelcontextprotocol.io/specification/2026-07-28/server/tools (tool names SHOULD, `inputSchema`/`outputSchema`, annotations untrusted, structured content, protocol errors vs tool execution errors, security considerations MUST list).
- MCP spec 2026-07-28, stdio: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio (stdout MCP only, stderr logging, newline framing, exit on stdin EOF, cancellation, backward-compatibility probe).
- `cargo info rmcp` run today: **3.6.0** is now the latest (Apache-2.0, rust-version 1.88; default features `base64`, `macros`, `server`). The clinic doc pinned 3.5.1; see D4.
- Repo code read at the baseline: `crates/core/src/transparency_log/{mod,receipt,checkpoint,record}.rs`, `merkle.rs`. Prior art: `../clinic-ops/docs/ARCHITECTURE-MCP.md` and `ARCHITECTURE-HOOK.md`.

**Carried over from the clinic-ops document, not re-verified today:** rmcp 3.5.1 smoke-test facts (macro usage `#[tool_router(server_handler)]`, `readOnlyHint` field, out-of-order responses, `serde_json` re-export); the 2025-06-18 revision comparison.
**UNVERIFIED:** how rmcp 3.6.0 handles the modern `server/discover` path, cancellation and `outputSchema` generation; whether the `rmcp` macros can declare `outputSchema` with `additionalProperties: false` as written here; the 2026-07-28 lifecycle and `server/discover` pages (not read); the effect of the fixed timeouts and caps under load; whether `readOnlyHint` is the field name in rmcp 3.6.0; JSON number handling above 2^53 (sizes are capped at 2^53-1 to stay exact).

## 14. Decisions
Settled by the reviewer on 2026-10-20: D1 yes (branch from the newest accepted tip), D2 file export first and HTTP later, D3 trust store from env only, D4 settled by the S2c rmcp smoke test, D5 keep the 64 KiB MCP cap, D6 fixed in core (S0g), D7 yes but in S5, D8 fine, D9 keep 128. Original text:
- **D2 log source:** v1 = `FileSource` over an exported log file (offline, fully testable) and `HttpSource` later against the public explorer API (S9)? Or HTTP first against the legacy `entropa-api` (`/api/chain/{partner}`, partner-scoped, with logins we plan to drop)? (Recommended: file first.)
- **D3 trust store:** keys only from `ENTROPA_TRUSTED_PUBKEYS`, or also a pinned key set compiled in for the KMS key? (Recommended: env only; document the KMS public key in the README.)
- **D4 rmcp version:** pin 3.5.1 (known smoke test) or 3.6.0 (latest)? Needs the compile smoke test in S2b.
- **D5 record size cap:** 64 KiB in the MCP layer versus the format's 1 MiB per field. Acceptable?
- **D6 index binding: CLOSED by S0g** (ADR 0016, `verify_inclusion_at`). Remaining limit: tree size is bound only by the signature.
- **D7 consistency tool:** a sixth tool `verify_consistency(old_checkpoint, new_checkpoint, proof)` for witnesses? Out of scope here; belongs with S5.
- **D8 rate limits:** 30/min and 10/min for `list_records` are borrowed from clinic-mcp, untested for real clients.
- **D9 label/preview length:** 128 chars. Enough for the data-minimal events planned in S9 (event type, actor key id, subject hash, outcome, reference)?
