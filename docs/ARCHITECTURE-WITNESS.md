# ARCHITECTURE-WITNESS: a tiny Azure witness for Entropa checkpoints

Status: design for review. **No Azure resource exists or is created by this document.** Nothing here is billable until
The owner says go. Written 2026-10-21.
The owner's Azure credit "pot B" ends about 2026-11-17, so section 9 plans how the work survives that date.

## 1. What a witness is for, and the honest limit
The log signs checkpoints (root, size, timestamp) with an ML-DSA-65 key held in AWS KMS. A log operator could show
two different histories to two different readers (a split view). A **witness** is an independent party, here in a
different cloud and account, that:
1. checks the checkpoint signature under the log's public key,
2. checks that the new checkpoint is an append-only extension of the last one *it* accepted (a Merkle consistency
   proof, RFC 6962/9162; `entropa_core::merkle::verify_consistency` already exists),
3. remembers the newest checkpoint it accepted, and
4. returns its own signed statement: "I saw this root at this size, extending what I saw before, at this time".

**What a witness proves:** that this witness saw checkpoint X, and that X extends the checkpoint it saw before. If a
reader holds a witness statement for X and a log checkpoint for the same size with a different root, the log
equivocated. **What it does not prove (state this wherever the witness is shown):**
- It does not prove what was *omitted*: records the log never appended, or a second history that was never shown to
  this witness, leave no trace here. A witness only constrains the history it was shown.
- One witness is one trust anchor. Its key, its clock and its operator (us) are single points of trust; a compromised
  witness key can sign anything. Real deployments use several independent witnesses and require a quorum.
- The first checkpoint a witness sees is accepted on trust (trust on first use); consistency is only checkable after that.
- Witness time is the witness's own clock, not a proof of when records were written.
- It proves nothing about whether the records are true, or an AI decision correct (see the decision records note).

## 2. Protocol
Request (JSON, strict decoder, size-limited, unknown fields rejected):
`{ "v": 1, "log_id": "<hex BLAKE3 of the log public key>", "checkpoint": {root, size, timestamp, proposer_pubkey, signature}, "consistency": ["<hex hash>", ...] }`
(`consistency` is empty for the first checkpoint and when the size is unchanged.)

The witness, in this order, and **fails closed** (a typed error, no signature) on any step:
1. `log_id` is configured, and `checkpoint.proposer_pubkey` is the configured key for it (no key from the request is trusted).
2. `Checkpoint::verify_signature(configured_pubkey)`.
3. Load the stored state `(size, root)` for the log. None: accept as first (TOFU) only if the log is flagged `allow_first`.
4. `new.size < old.size`: reject (rollback). `new.size == old.size`: roots must be equal, else reject as **equivocation** and record it
   (see 2.1). `new.size > old.size`: `verify_consistency(old.root, old.size, new.root, new.size, proof)` must hold.
5. Build and sign the statement. **Nothing is released yet.** (S5b change: signing happens before the swap, so a signer failure can never leave the state advanced without a statement.)
6. Compare-and-swap the state to `(new.size, new.root)` (storage ETag / `If-Match`), so two concurrent requests cannot both advance from the same old state. Only when the swap succeeds is the statement returned; a lost race is a retryable `StoreConflict` and the signed statement is discarded.

Details fixed by the S5b tests: the first checkpoint of a log is accepted only when `allow_first` is on and no state exists; a stored size of 0 (an empty log) is extended by any larger checkpoint with an **empty** proof (a non-empty proof is refused); an unchanged size needs an empty proof and the same root, and is accepted again without changing the state; `previous_size` / `previous_root` in the statement are `0` / `NO_PREVIOUS_ROOT` (64 zeros) for the first checkpoint; a witness refuses to be built when a configured `log_id` is not the BLAKE3 of its key or appears twice.

Witness statement (canonical JSON, keys sorted at every level, no whitespace; signed over
`BLAKE3("entropa-witness-statement-v1" 0x00 || u32be(len) || canonical)` like the other signed records):
`{ "v":1, "type":"witness.cosign", "log_id", "size", "root", "log_timestamp", "witness_time", "previous_size", "previous_root", "witness_pubkey", "sig" }`.
Only hashes, sizes and times are in it; never record contents. The decoder is strict (exact field set, lowercase hex, bounded ints), like the approvals and policy records. Golden vectors come from an independent Python generator as in earlier stages.

### 2.1 Equivocation record
(A flood of bad proofs from a valid log signature would grow this blob: cap the number of evidence entries per log in the Azure adapter, S5d.)
When step 4 finds the same size with a different root, or a signed checkpoint that fails consistency, the witness returns an error **and** appends an
`equivocation` entry (both checkpoints, as received) to its own evidence blob. That entry is the thing worth publishing: two log-signed checkpoints that cannot both be true.

## 3. Components and where they run
| Part | Where | Notes |
|---|---|---|
| `entropa-witness` crate (S5b/S5c) | repo | Pure core: decode, verify, state transition, statement signing. No cloud types. Typed errors, no panics on untrusted input, fuzz target, proptest, mutation, like earlier crates. A `StateStore` trait (get / compare-and-swap) and a `StatementSigner` trait (same shape as `CheckpointSigner`). |
| Azure adapter (S5d) | repo, `infra/azure/witness/` | A small Rust HTTP binary using the Azure Functions **custom handler** protocol (no container, no ACR): zip-deployed. `StateStore` = one blob with ETag compare-and-swap. |
| Function app | Azure, region TBD (D2) | Consumption hosting, HTTPS only, one route `POST /cosign`, plus `GET /pubkey`. No other endpoints. |
| Storage account | Azure | Standard_LRS StorageV2, public blob access off, TLS 1.2: the Function host needs it anyway; also holds the state blob and the equivocation blob. |
| Key Vault (Standard) | Azure | Holds the witness signing key material as a secret (see 4), read by managed identity with the *Key Vault Secrets User* role. |
Not used on purpose: Container Registry (cost), Application Insights / Log Analytics (cost; the witness logs hashes and sizes only, to the function log stream that the platform keeps for free). Hosting alternative B: Azure Container Apps (consumption) with a public image; needs an image published to a public registry (an outward-facing step for the owner) and its idle environment charge must be confirmed first (section 6), so it is the fallback, not the pick.

## 4. Key custody (the weak spot, stated plainly)
The log key is an AWS KMS ML_DSA_65 key that never leaves KMS. For the witness:
- Azure Key Vault and Managed HSM: **native ML-DSA key types were not found in this session.** A secondary source (Encryption Consulting comparison) says they are not available yet; I did not find a Microsoft primary source either way. This must be checked against Microsoft's "supported key types" page before S5d (D1).
- Therefore the S5 demo witness holds a **software ML-DSA-65 key** generated outside Azure, stored as a Key Vault secret, loaded into memory by the function. Anyone with Contributor rights on the vault or the app can obtain it. Mitigation inside the design: the key is only for witness statements, it is rotatable (the witness public key is published in the evidence and the verifier takes it as an explicit input), and nothing else trusts it. This is a real limit and is shown in the write-up.
- If Azure ships HSM-backed ML-DSA by build time, switch the `StatementSigner` to it; the trait boundary makes that a small change.

## 5. Threats (short STRIDE, witness only)
| Threat | Mitigation |
|---|---|
| Spoofed log (request from an attacker with a different key) | Configured log key only; request key ignored; step 1-2 |
| Rollback / old checkpoint replay | Monotonic state with compare-and-swap; smaller size rejected; equal size must match root |
| Split view by the log | Detected only for the history this witness is shown; equivocation recorded (2.1) |
| Forged witness statement | Statement signed with the witness key; verifier takes the witness public key from the evidence |
| Key theft (software key) | Section 4; rotation; limited blast radius (a forged cosignature, not log access) |
| DoS / flooding | Request size cap (64 KiB), proof length cap, Function platform throttling; **witness outage must never block log appends** (the log does not call it synchronously) |
| Information leak | Only checkpoints in, only hashes/sizes/times out; no record contents ever reach the witness |
| Cost abuse (billing attack) | Anonymous endpoint is the risk: request cap + a shared bearer token in a header checked before any work (stored in Key Vault); budget alert set before deploy; daily cap on executions in the app settings |

## 6. Price first (Azure Retail Prices API, fetched 2026-10-21, region `westus2`, currency USD, retail list prices)
The API lists meters, not free grants as such: a row with price 0.0 and a higher `tierMinimumUnits` row is a free tier.
| Meter | Price | Free tier shown by the API |
|---|---|---|
| Functions, Standard (classic Consumption) total executions | $0.000002 per 10 executions (= $0.20 per million) | first 1,000,000 free |
| Functions, Standard execution time | $0.000016 per GB-second | first 400,000 GB-s free |
| Functions, Flex Consumption on-demand executions | $0.000004 per 10 (= $0.40 per million) | first 250,000 free |
| Functions, Flex Consumption on-demand execution time | $0.000026 per GB-second | first 100,000 GB-s free |
| Blob Storage Hot LRS data stored | $0.0184 per GB-month | none |
| Blob Hot LRS write / read / other operations | $0.05 / $0.004 / $0.004 per 10,000 | none |
| Key Vault Standard operations | $0.03 per 10,000 | none; I saw no per-vault monthly fee among the 14 rows I read (the listing was cut at 14, so confirm) |
| Container Apps (fallback) consumption vCPU / memory active | $0.000034 per vCPU-s / $0.000004 per GiB-s | free grants are **not** in the price API |
| Container Apps "Environment Management Hour" | $0.10 per hour | unknown whether it applies to a consumption-only environment: confirm before choosing B ($0.10/h would be about $73 a month) |

**Forecast (classic Consumption, option A), assuming 1,000 cosign requests a month, 0.25 s each, 128 MB:**
compute 32 GB-s and 1,000 executions: inside both free tiers = **$0.00**; state blob (1 KB) and writes: 1,000 writes about $0.005; Function-host
storage traffic (heartbeats, locks): assumed up to about 100,000 operations a month about $0.50; Key Vault reads at cold start: negligible (< $0.01).
**About $0.01 to $1 a month; worst case about $0.0014 per hour.** Idle cost is the storage account only (cents). These are forecasts; the actual comes from
Cost Management (section 9). Ledger rows for these (marked proposed, not created) are in the cost notes. A budget alert of $5 is created *before* any resource (it is free).

**Pick: option A, Functions classic Consumption on Linux with a custom handler.** Linux Consumption retires on 2028-09-30 per Microsoft's notice (found by search, confirm), which is long after Nov 17. Flex Consumption is the successor; its custom-handler support appeared supported in search results but unclear: check (D3). Cheapest viable SKU in either case is the pay-per-use plan, not a dedicated plan.

## 7. Teardown (the owner runs it; an agent deletes nothing)
Everything lives in one resource group `rg-entropa-witness`, tagged `project=entropa`. After the capture (section 9) the owner runs:
```
az group delete --name rg-entropa-witness --yes --no-wait     # removes every resource of the witness
az group exists --name rg-entropa-witness                      # prints false when gone
```
A Key Vault is soft-deleted for 90 days by default; to free the name earlier the owner may also run `az keyvault purge --name <vault>` (kept out of scripts on purpose). Nothing is left running after teardown. Deletion requires explicit approval.

## 8. Test plan (red first, each stage on its own branch, like S4)
S5b stubs + red tests; S5c implement; S5d Azure adapter + Bicep (no deploy); S5e deploy (billable: the owner's go, price stated again); S5f capture.
- Known-answer vectors from an independent Python generator (statement digest, canonical bytes, consistency cases).
- W1 happy path: first checkpoint (TOFU), then extension with a valid proof.
- W2 rollback rejected; W3 same size different root = equivocation (recorded); W4 bad proof, wrong-length proof, proof for another pair.
- W5 wrong log key / request-supplied key ignored; W6 tampered signature; W7 unknown log_id.
- W8 compare-and-swap loser gets a retryable error and signs nothing; W9 store failure = no signature (fail closed).
- W10 strict decoder: unknown fields, oversize, bad hex, big integers; fuzz target for the request decoder and the statement decoder.
- W11 property test: random append histories, witness accepts exactly the consistent ones.
- Static guards: no secret read paths, size limits present, the adapter exposes only `/cosign` and `/pubkey`.
- Mutation run capped (container limits from S0h), equivalents documented.

## 9. Azure evidence capture: keeping the work after the credit ends (about 2026-11-17)
Goal: everything the witness proved and cost is captured as files in this repo before teardown, and the whole thing can be redeployed on any subscription with one command.
1. **Infrastructure as code.** `infra/azure/witness/main.bicep` (+ `main.bicepparam`): resource group scope, storage account, plan, function app, Key Vault, role assignments, tags `project=entropa`, a budget (free). One command: `az deployment group create -g rg-entropa-witness -f infra/azure/witness/main.bicep -p infra/azure/witness/main.bicepparam`. `az deployment group what-if` runs first (free) and its output is saved. Compile/lint with `az bicep build` in S5d (read-only, allowed).
2. **Capture scripts** (read-only `az` commands only; they refuse to run if a command outside an allow-list would be used; they never print secret values: `--query` selects names, ids, SKUs and outputs, app settings are listed by *name* only; checked by a secret-pattern scan before saving):
   - `scripts/azure/capture-deployment.sh`: `az deployment group show` outputs, `az resource list` JSON with tags and SKUs.
   - `scripts/azure/capture-cost.sh`: Cost Management query for the group (actual to date, daily), plus the forecast from section 6 side by side; also `az consumption usage list` when available.
   - `scripts/azure/capture-witness.sh`: sends N synthetic checkpoints (including one rollback and one equivocation test) to the live witness, saves every request and response.
   - `crates/witness/examples/verify_witness.rs`: re-verifies every saved response with **our own verifier** (log signature, consistency, witness signature under the published witness key). The captured evidence is only valid if this passes offline, after Azure is gone.
3. **Runbook** `docs/runbooks/azure-witness.md`: deploy, smoke test, cost per hour and per month (section 6, replaced by the measured numbers), the teardown commands (section 7), what to do if the endpoint is attacked (rotate token, stop the app: `az functionapp stop`, which the owner runs).
4. **Evidence folder** (committed; no secrets, no tokens):
```
docs/evidence/azure/
  README.md                 what each file is and the one command that re-verifies it
  deploy/                   what-if.txt, deployment-outputs.json, bicep-build.txt
  resources/                resource-list.json, sku-and-tags.json
  cost/                     forecast.md, cost-actual.json, budget.json
  witness-responses/        req-NNN.json, resp-NNN.json, witness-pubkey.hex, equivocation-test.json
  verify/                   verify-witness.txt (our verifier's output), verify.sh
  writeup.md                from the template below
```
5. **Write-up template** (for the public site and the book; filled from the evidence, never from memory):
```
# Entropa witness on Azure: what was built, what it proved, and the limits
Built: <services, SKUs, region, deploy date, one-command redeploy>.
Proved: <N checkpoints cosigned; consistency verified; rollback and equivocation tests rejected; every response re-verified offline by our verifier (output attached)>.
Exact limits: <the five limits in section 1, plus software key custody (section 4), single witness, TOFU>.
Cost: forecast <$> vs actual <$> (Cost Management export attached); teardown date <date>.
Reproduce: <repo path, command, expected output>.
```
6. **Schedule** (today is 2026-10-21): design accepted and S5b/S5c (pure crate, no cloud) by about Oct 28; S5d adapter + Bicep + what-if by Nov 1; S5e deploy **only with the owner's go and the price restated**, by about **Nov 5**; capture and offline re-verification by **Nov 10**; margin to **Nov 17**; teardown run by the owner right after the capture is verified (not on the last day). If the deploy slips past Nov 8, the fallback is to skip the live run and ship the Bicep, the what-if output and the offline verifier test against recorded vectors, and say so.

## 10. Decisions for the reviewer and the owner
- **D1 Key custody:** accept the software key in Key Vault (section 4) for the demo, or wait for HSM-backed ML-DSA? Verify Azure's supported key types first. Recommendation: accept, with the limit stated.
- **D2 Region:** pick the cheapest region that has the services (price above is `westus2`; check the same meters for the region the owner's subscription uses before deploy).
- **D3 Hosting:** classic Consumption (A) vs Flex Consumption vs Container Apps (B). Recommendation: A; confirm custom-handler support and retirement dates in Microsoft's docs at the start of S5d.
- **D4 Endpoint protection:** bearer token plus request caps (section 5), or private access only? Recommendation: token plus caps, and a $5 budget alert before deploy.
- **D5 First checkpoint:** TOFU with `allow_first` on the very first request only. Recommendation: yes, recorded in the evidence.
- **D6 Quorum:** one witness for the exam showcase; the doc says a real deployment needs several. A second witness (GCP) could be a later stage.
- **D7 Statement format:** our own ML-DSA statement now; a C2SP-style cosignature is out of scope (it targets classical keys).
- **D8 Region of the budget alert and subscription IDs** stay out of the repo (no identifiers of the account are committed).
