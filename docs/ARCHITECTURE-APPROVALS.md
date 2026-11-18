# ARCHITECTURE-APPROVALS: signed approval records and a human gate (`entropa-approvals`)
Status: **design only, no code** (stage S3a, 2026-10-20). A proposal for the reviewer and the owner. Items I could not confirm are marked **UNVERIFIED**; open decisions are in section 12.

Note on role names: `builder-agent`, `orchestrator-agent` and `human-principal` (and the council's `critic-agent` and `contestor-agent`) are generic example roles of the access model, not a statement about how any particular team works.

## 1. Purpose
Some actions must not happen on an AI's own say-so: deletes, spend, publishing, merges, deploys, policy changes (the project rules, the global rules, a project record (not published) "human gates"). Today those approvals live in chat. This stage makes them **records in the Entropa log**: a *request*, then an *approve* or *deny* **signed by the approver's key**, and a **gate** that answers "is there a valid, unexpired, unused approval for exactly this action?". The ledger proves who approved what and that it was not changed afterwards; it does not prove the approval was wise (docs/AI-POLICY note).

## 2. Scope
In S3: the event model, canonical encoding, signing and verification, the actor directory, the replay state machine, and the gate check as a pure library (`crates/approvals`), writing to and replaying from a `TransparencyLog`. **Not** in S3: a CLI or phone approval, the hook calling the gate, Cedar policy (S4), witnesses (S5), the public explorer and per-actor KMS keys (S9), any cloud call.

## 3. Event model (data-minimal)
Each event is one Entropa record (record format v2): payload = canonical JSON of the event, label = `approval.request`, `approval.approve` or `approval.deny`. Only these fields exist; every text field is a fixed vocabulary, a hash, or a short token (charset `A-Za-z0-9._:/-`, at most 64 characters). **Never** conversation text, secrets or personal/health data; the chat reference is carried as a hash.

| Field | Events | Meaning |
|---|---|---|
| `v` | all | schema version, `1` |
| `type` | all | `request`, `approve`, `deny` |
| `request_id` | all | 64 hex: `BLAKE3("entropa-approval-request-id-v1" 0x00 || requester key id || 0x00 || action class || 0x00 || subject hash || 0x00 || ts as decimal text)` so it cannot be chosen freely |
| `actor` | all | key id (16 hex, first 8 bytes of BLAKE3 over the public key) of the signer |
| `ts` | all | unix seconds claimed by the signer |
| `action_class` | request | one of `delete`, `spend`, `publish`, `merge`, `deploy`, `direction`, `policy_change`, `credentials_change` (D1) |
| `subject_hash` | request | 64 hex: BLAKE3 of the exact thing to be approved (the command, the resource list, the diff) |
| `subject_ref` | request | short token such as a commit SHA or stage id |
| `valid_for_secs` | request | how long an approval stays usable, 60 to 604800 (default 86400, D3) |
| `reason_code` | deny | `not_authorised`, `wrong_subject`, `too_risky`, `other` |
| `on_behalf_of` | approve, deny | key id of a human who has no signing key yet; makes the event an **attestation** (section 6) |
| `basis_hash` | approve, deny | optional BLAKE3 of the chat reference string, never the text |
| `sig` | all | ML-DSA-65 signature, hex |

## 4. Signing and canonical form
- Canonical bytes: the event as JSON with keys sorted, no whitespace, `sig` removed.
- Signed digest: `BLAKE3( "entropa-approval-v1" 0x00 || u32be(len) || canonical bytes )` (domain separation, length-prefixed, as in record format v2), signed through the existing `CheckpointSigner` trait, so a `Probe` in development and an AWS KMS key in production work the same.
- The stored payload is the canonical JSON with `sig` added. The decoder is strict: unknown fields, wrong types, uppercase hex, oversize tokens, or a `v` other than 1 reject the event (it is logged by the replay as `rejected`, never silently dropped).

## 5. Actor directory and rules
The directory maps key id to `{public key, role, may_approve: [action classes], may_attest_for: [key ids], status}`. In S3 it is a value passed to the library (loaded from a configuration file or built in tests); in S9 it becomes ledger records (`actor.register`, `actor.revoke`). Roles: `human`, `ai`, `service`.
Validity rules (the replay applies them in log order; an event that breaks one is `rejected` with a reason code):
1. The `actor` key id must be in the directory and `active`, and the signature must verify under its public key.
2. A **request** may be made by any active actor.
3. A **decision** must come from an actor whose `may_approve` includes the request's action class, and the approver must differ from the requester (**no self-approval**).
4. A decision must come **after** its request in log order, and before the request's expiry (`request.ts + valid_for_secs`, measured on the gate's own clock at check time and on `ts` at replay time).
5. **First valid decision wins** (D4): later decisions for the same request are recorded as `superseded` and never change the outcome.
6. Timestamps more than 5 minutes ahead of the replay clock are rejected (clock skew).
7. A key revoked at log index N cannot sign events recorded after N.

## 6. Attestation: "attested by the reviewer"
The owner has no signing key yet. Until he has one, the reviewer may record his decisions with `on_behalf_of` = the owner's key id, signed by the reviewer. The directory entry for the owner has `signing_key: none` and `attestable_by: [the reviewer]`. The gate reports such an approval as `attested: true`, with both key ids, so nothing can mistake it for the owner's own signature. **Hard rule (the reviewer, 2026-10-20, overrides the first proposal for D2):** an attestation can never make the gate return `Allowed` for a hard-rule class: `delete`, `spend`, `publish` and `credentials_change` (and any billing action, which is `spend`). The owner's hard rules require his own word in chat plus a standalone yes/no, and a `basis_hash` is only a hash the gate cannot check, so the reviewer alone could otherwise authorise a delete. For those classes the gate answers `Blocked(attestation_not_accepted)` until the owner holds his own signing key; the attested event is still **recorded** for the audit trail. An attestation yields `Allowed` only for `direction` (a recorded decision, not an authority to act); for every other class, hard-rule or not (merge, deploy, policy_change included), the gate answers `Blocked(attestation_not_accepted)`. The policy argument of the gate can only narrow this, never widen it (found by the property test P1 on a later random seed, fixed in S3c). The ledger records approvals; it is never the authority for hard-rule actions until the owner holds a key. The target state is the owner's own key and a one-tap approval; that is not S3.

## 7. The gate
`Gate::check(state, action_class, subject_hash, now)` answers `Allowed { request_id, approver, attested }` or `Blocked { reason }` with reason one of `no_request`, `pending`, `denied`, `expired`, `already_used`, `subject_mismatch` (a request exists for the class but for a different subject), `attestation_not_accepted`. An approval is **single use**: the executor records `approval.consume` (actor, request id) after acting, and the gate then answers `already_used`. The gate is a pure function of the replayed state, so it is testable without a network. It never creates or alters records.

## 8. Writing and reading
`append_event(&mut TransparencyLog, &Event)` encodes and appends (returns the log index). `replay(&TransparencyLog, &Directory, now) -> State` decodes every record in order, verifies, applies the rules, and returns the state plus the list of rejected events with reasons. Receipts for the events come from the log as usual, so a third party can verify that an approval is in the log with `verify_receipt` and read the event.

## 9. Threats
| Id | Threat | Mitigation |
|---|---|---|
| A1 | Forged approval | signature verification against the directory; unknown key rejected |
| A2 | AI approves its own request | rule 3 (requester differs; approvers are listed per class, AI roles are not) |
| A3 | Approve X, do Y | the approval is bound to `subject_hash`; the gate compares the action's own hash |
| A4 | Replay of an old approval | expiry, single use via `approval.consume` |
| A5 | Approval for one class reused for another | binding to `action_class` |
| A6 | Tampered stored event | signature breaks; log inclusion proof and checkpoint signature |
| A7 | Backdated or future events | skew rule; ordering by log index, not `ts` |
| A8 | Stolen or retired key | revocation records effective by log index (rule 7); production keys only in KMS |
| A9 | Attestation abuse (the reviewer claims the owner approved) | explicit `on_behalf_of` and `attestable_by` list; the gate never returns `Allowed` on an attestation for delete, spend, publish or credentials_change (fixed in code); for `direction` the result is labelled `attested`; `basis_hash` ties the event to a chat reference for later review; the owner can review attested events |
| A10 | Omission (an approval was never recorded, or an action ran without asking) | **cannot be proven absent by the ledger**; mitigations: the hook (S2h) blocks the action classes until the gate allows (later stage), chain-head anchoring, witnesses (S5) |
| A11 | Free text smuggling (secrets, patient data) | no free-text fields; strict charset and length; unknown fields rejected |
| A12 | Race: approve and deny arrive together | rule 5, order is the log order |

## 10. Test plan (S3b writes these red; S3c makes them green)
Fixtures: throwaway `Probe` keys for the owner-stand-in human, the reviewer (ai, attestor), the author (ai requester), a service, and a directory built in the test. All data synthetic.
| Id | Case | Expected |
|---|---|---|
| E1 | encode/decode round trip of each event type | equal; canonical bytes stable (golden vector, generated independently) |
| E2 | reject: unknown field, uppercase hex, token with a space, 65-char token, `v` 2, missing `sig`, `valid_for_secs` 59 and 604801, unknown action class | decode error naming the field, never echoing the value |
| E3 | signature covers every field (flip each one) | verification fails |
| R1 | request then approve by an allowed human | gate `Allowed`, `attested` false |
| R2 | request then deny | `Blocked(denied)` |
| R3 | request only | `Blocked(pending)`; nothing at all: `Blocked(no_request)` |
| R4 | approval after expiry on the gate clock | `Blocked(expired)` |
| R5 | self-approval; approver without `may_approve` for the class; AI approver | event rejected, gate stays `pending` |
| R6 | wrong signature; unknown key; revoked key (before and after the revocation index) | rejected / accepted as specified |
| R7 | decision before its request in log order | rejected |
| R8 | approve then deny (and deny then approve) | the first wins, the second is `superseded` |
| R9 | subject hash differs from the action's | `Blocked(subject_mismatch)` |
| R10 | consume, then check again | `Blocked(already_used)` |
| R11 | attestation by the reviewer for the owner: for `direction` the gate answers `Allowed{attested:true}`; for `delete`, `spend`, `publish` and `credentials_change` it answers `Blocked(attestation_not_accepted)` even with a `basis_hash` and even if the policy argument lists the class; the attested events are still recorded (no rejection) | as stated |
| R12 | event `ts` 10 minutes in the future | rejected (skew) |
| L1 | events appended to a `TransparencyLog`, replayed, receipts verified with `verify_receipt` | state equals the in-memory result; every receipt verifies |
| L2 | replay is deterministic and independent of how many checkpoints were taken | equal state |
| L3 | a non-approval record in the same log | ignored, not rejected |
| P1 | proptest: random event sequences never make the gate allow without a valid approve by an allowed, different actor | invariant holds |
| F1 | fuzz target for the event parser | no panic |
| N1 | static guards | no network, no process spawn, no `unsafe`, no file writes in the crate |

## 11. Documentation used and not verified
Read for this design: a project record (not published), the project rules laws L3 L4 L5 L11, a project record (not published) S3/S9, docs/ARCHITECTURE-MCP.md, the design of the agent guard (not published), `crates/core` (record format v2, `CheckpointSigner`, `verify_receipt`). No external standard is cited. UNVERIFIED: whether the `CheckpointSigner` trait suits per-actor approval signing without changes (it signs arbitrary bytes, which should suffice); the 5-minute skew value and the 24 h default are proposals; the interplay with the hook and with Cedar is design intent only.

## 12. Open decisions
- **D1** the action-class vocabulary (eight classes listed) and whether `direction` (the owner's choices of course) belongs.
- **D2 (decided by the reviewer):** attestation counts as `Allowed` for `direction` only; delete, spend, publish and credentials_change block with `attestation_not_accepted` until the owner has a key. Attested events are still recorded.
- **D3** default validity 24 hours, maximum 7 days.
- **D4** first valid decision is final (proposal) versus deny always wins.
- **D5** events as JSON inside record format v2 (proposal) versus a binary encoding.
- **D6** directory as a configuration file now and ledger records in S9 (proposal).
- **D7** where the gate is called: the hook for `delete`/`spend`/`publish` classes (next stage), a CLI, the MCP server stays read-only.
- **D8** `approval.consume` written by the executor itself (proposal) or by the gate on a successful check.
- **D9** keys: development uses local `Probe` keys; production approvers use KMS ML-DSA-65 keys (about $1 per key per month, priced and approved by the owner before creation, L11).
