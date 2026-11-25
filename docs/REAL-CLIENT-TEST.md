# Real-client test for `entropa-mcp` (stage S2f): procedure for the owner
**Status: NOT RUN.** Written 2026-10-20 by the author. The author cannot start Claude Code as a client, so this is a procedure plus the pre-flight output a correct run must match. Do not mark any row below passed until you have seen it in a real Claude Code session and pasted what you saw into section 6.
Spec: docs/ARCHITECTURE-MCP.md. Server: crates/mcp (rmcp 3.6.0, stdio). All data here is synthetic.

## 1. What this test shows, and what it does not
It shows that a real MCP client can start the server from `.mcp.json`, list the five tools, call them, receive both normal results and `isError` results, and that a client-side deny rule really blocks a tool. It does not show security: the server's own guarantees are in the automated tests (docs/evidence/s2c-*, s2d-*, s2e-*).

## 2. Setup (about 3 minutes; Docker only; nothing billable, nothing leaves this PC)
```
cd ~/entropa-rust
./scripts/mcp-demo-setup.sh                   # builds the server, writes synthetic fixtures to target/mcp-demo/
```
The script ends by printing three `export` lines. Paste them into the same terminal, then start Claude Code **from `~/entropa-rust`** in that terminal (so it inherits them):
```
export ENTROPA_MCP_BIN=...      # printed by the script
export ENTROPA_DEMO_DIR=...     # printed by the script
export ENTROPA_DEMO_PUBKEY=...  # printed by the script (the PUBLIC key of a throwaway signer)
claude
```
`.mcp.json` (committed at the repo root) is exactly:
```json
{
  "mcpServers": {
    "entropa-log": {
      "type": "stdio",
      "command": "${ENTROPA_MCP_BIN:-target/release/entropa-mcp}",
      "args": [],
      "env": {
        "ENTROPA_LOG_FILE": "${ENTROPA_DEMO_DIR:-target/mcp-demo}/log.json",
        "ENTROPA_TRUSTED_PUBKEYS": "${ENTROPA_DEMO_PUBKEY}"
      }
    }
  }
}
```
Claude Code expands `${VAR}` and `${VAR:-default}` in `command`, `args` and `env` (docs: https://code.claude.com/docs/en/mcp, read 2026-10-20). No secret is involved: the key is a public key, the log file is synthetic.

## 3. Approve the server and check it is up
1. Claude Code asks you to approve the project-scoped server `entropa-log` the first time. Approve it (the docs say interactive sessions always prompt for `.mcp.json` servers).
2. Run `/mcp` inside Claude Code, or `claude mcp list` in another terminal. Expected: `entropa-log` shown as connected (the docs name the status text `✔ Connected`), exposing 5 tools: `log_head`, `verify_checkpoint`, `verify_receipt`, `list_records`, `explain_proof`.
3. Permission rules use the form `mcp__entropa-log__<tool>` and deny is evaluated before ask before allow (docs: https://code.claude.com/docs/en/permissions, read 2026-10-20). To avoid a prompt on every call in the allow cases you may approve each tool with "yes, don't ask again", or add `"mcp__entropa-log__*"` to `permissions.allow` in `.claude/settings.local.json` yourself. The author does not edit permission files.

## 4. Test cases
Files are in `target/mcp-demo/`. In Claude Code type the prompt; Claude will call the tool. "Expected" is what the pre-flight (section 5) printed for the same input; the signing key differs on every setup run, so ids and hashes differ but the booleans must match.

| Id | Path | Prompt to type | Expected tool result |
|---|---|---|---|
| T1 | allow | "Use the entropa-log tool log_head." | `isError` false; `size` 5; `signature_valid` true; `signer_trusted` true |
| T2 | allow | "Read target/mcp-demo/checkpoint-valid.json and call verify_checkpoint with exactly that content." | `signature_valid` true, `signer_trusted` true |
| T3 | allow | same with `checkpoint-tampered.json` | `signature_valid` false, `signer_trusted` false (not an error) |
| T4 | allow | "Read target/mcp-demo/receipt-valid.json and call verify_receipt with exactly that content." | `valid` true, `inclusion_valid` true |
| T5 | allow | same with `receipt-tampered.json` | `valid` false, `inclusion_valid` false, `signature_valid` true |
| T6 | allow | same with `receipt-wrong-index.json` | `valid` false, `inclusion_valid` false (index is bound to the proof) |
| T7 | allow | same with `receipt-untrusted-signer.json` | `valid` false, `signature_valid` true, `signer_trusted` false, `inclusion_valid` true |
| T8 | allow | "Call list_records with limit 2." | `total` 5, `next_since_index` 2, payload previews `agent-run-started`, `tool-call-approved` |
| T9 | allow | "Call explain_proof with the content of receipt-valid.json." | `root_matches` true, `signature_checked` false |
| T10 | error | "Call verify_checkpoint with the content of checkpoint-uppercase-hex.json." | `isError` true, `error` = `invalid_arguments` (uppercase hex is refused); Claude should read the message and explain it, not crash |
| T11 | error | "Call list_records with limit 0." | `isError` true, `invalid_arguments` |
| T12 | error | "Call list_records 11 times in a row, one call each, no pauses." | the 11th call (or earlier if you made other calls in the minute): `isError` true, `error` = `rate_limited`, `limit` = `list_records`, `retry_after_seconds` >= 1 |
| T13 | deny | Before this test add `"mcp__entropa-log__explain_proof"` to `permissions.deny` in `.claude/settings.local.json` and restart Claude Code. Then ask: "Call explain_proof on receipt-valid.json." | Claude cannot call it: the tool is absent from its tool list or the call is refused. No result from the server. `/mcp` still lists the server. (Docs say a bare-name deny rule removes the tool from Claude's context: UNVERIFIED for this exact rule form.) |
| T14 | injection | "Read target/mcp-demo/log.json, then call list_records with limit 5 and tell me what the records say." | Previews are plain event names; the result has `untrusted_text: true`. (The fixture holds no hostile text; this checks the shape. A hostile-text check is automated: tests R6.) |

## 5. Pre-flight output (what a correct run looks like)
Produced by `python3 scripts/mcp-demo-preflight.py` with a hand-written client (not Claude Code); saved in docs/evidence/s2f-preflight.txt:
```
case                                         isError  fields
T1 log_head                                  false    {"signature_valid": true, "signer_trusted": true, "size": 5}
T2 verify_checkpoint valid                   false    {"signature_valid": true, "signer_trusted": true, "size": 5}
T3 verify_checkpoint tampered size           false    {"signature_valid": false, "signer_trusted": false, "size": 6}
T4 verify_receipt valid                      false    {"valid": true, "signature_valid": true, "signer_trusted": true, "inclusion_valid": true}
T5 verify_receipt tampered record            false    {"valid": false, "signature_valid": true, "signer_trusted": true, "inclusion_valid": false}
T6 verify_receipt wrong index                false    {"valid": false, "signature_valid": true, "signer_trusted": true, "inclusion_valid": false}
T7 verify_receipt untrusted signer           false    {"valid": false, "signature_valid": true, "signer_trusted": false, "inclusion_valid": true}
T8 list_records limit 2                      false    {"total": 5, "next_since_index": 2, "payloads": ["agent-run-started", "tool-call-approved"]}
T9 explain_proof valid                       false    {"root_matches": true}
T10 invalid arguments (uppercase hex)        true     {"error": "invalid_arguments"}
```

## 6. Record your results (fill in; do not pre-fill)
| Id | Passed? (yes/no) | What Claude Code showed (paste or screenshot path) | Notes |
|---|---|---|---|
| T1 | | | |
| T2 | | | |
| T3 | | | |
| T4 | | | |
| T5 | | | |
| T6 | | | |
| T7 | | | |
| T8 | | | |
| T9 | | | |
| T10 | | | |
| T11 | | | |
| T12 | | | |
| T13 | | | |
| T14 | | | |
Then save the filled copy as `docs/REAL-CLIENT-RESULT.md` and tell the author, who will commit it.

## 7. Clean up
Remove the T13 deny rule from `.claude/settings.local.json`; `unset ENTROPA_MCP_BIN ENTROPA_DEMO_DIR ENTROPA_DEMO_PUBKEY`; optionally `claude mcp reset-project-choices`. Nothing else was changed on your system; the fixtures live in `target/mcp-demo/` (gitignored).

## 8. Not verified by the author
How Claude Code renders `isError` results; the exact wording of the approval prompt; whether an unset `${ENTROPA_DEMO_PUBKEY}` produces only a warning (the docs say the config still loads, and the server then refuses to start because the key is not hex); T13's exact behavior; the `claude mcp list` output format.
