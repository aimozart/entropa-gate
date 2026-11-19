# ARCHITECTURE-EXPLORER: the public explorer and demo, no login

Status: design for review. **No GCP or other resource is created by this document.** Written 2026-10-21 on branch
Nothing here is billable until the owner says go with the price restated.
Rules carried over: synthetic data only; no secrets in the repo or the browser; nothing is deleted without explicit approval; no compliance claim of any kind; the GCP project is `entropa-testnet` (the one GCP project).

## 1. What it is, and what it is not
A public, read-only window onto the Entropa ledger: anyone can open it, look at checkpoints, records, receipts and proofs, see witness
statements and the people-and-agents who act, and **verify a record in their own browser** without trusting our server.
**Not in it, by design:** no login, no signup, no billing, no API keys, no partner accounts, no payment page, no ingest endpoint, no cookies, no
tracking, no personal data. The old product surface (partner login dashboard, `/api/tx` ingest, admin UI, billing) is retired; the explorer never writes
to the ledger. Only the server-side generator (section 6) and the real approval flows write, and they are not reachable from the internet.

## 2. What exists today (inventory, so the migration is honest)
| Part | State |
|---|---|
| `website/public-main` (Firebase Hosting target `main`, entropa.space) | 12 HTML pages (10 top level, 2 in subfolders): marketing home (47 KB, AML/KYC bank pitch, pricing and "$0.01 per attestation" claims, 6 dead `/signup` links), trust, sla, glossary, contact, hire, resume, privacy, terms, login `dashboard.html`, `demo/dashboard.html`, `dashboard/explorer.html` (the partner explorer behind the login) |
| `website/public-scryon` (target `scryon`, scryon.entropa.space) | "Scryon", the demo explorer: `index.html`, `flow.html` (live feed from `https://api.entropa.space/demo/feed`); backed by a Cloud Run service `entropa-scryon` of the legacy Java product |
| Look | dark theme with gradient orbs and a drifting grid; generic; reused on every page |
The new explorer replaces Scryon and the demo feed. Nothing live is touched by this stage.

## 3. Architecture (read path is static-first, serverless, scale to zero)
```
 browser --> Firebase Hosting (static front end + WASM verifier, global CDN)
                |  /api/**  rewrite (GET only, cacheable)
                v
        Cloud Run "explorer-api" (Rust, min instances 0, max 3, in-memory rate limit)
                |  reads a snapshot + generation number
                v
        Cloud Storage bucket "ledger" (append-only objects: records, checkpoints, witness statements, actor directory)
                ^  writes (preconditioned on the generation, so it can only append)
        Cloud Run Job "generator" (synthetic AI decisions, the single writer) <-- Cloud Scheduler (every 10 minutes)
                |  uses entropa-core, entropa-approvals, entropa-policy, entropa-witness (the real crates)
                +--> keys: Secret Manager (demo actor keys, software ML-DSA); log checkpoint key: see D3
        witness statements: pushed in by the witness (S5, Azure) or by a second generator-side witness; stored beside the checkpoints
```
Why this shape: the ledger is small (thousands of events), so the read API loads a snapshot at cold start and computes proofs on demand with the
same `entropa-core` code that the verifier uses; the CDN absorbs repeat traffic because every response about a past state is immutable and cacheable. Only
`/api/head` changes (short cache).

## 3.1 Where language models run (DECIDED by the owner, 2026-10-21)
LLMs run in exactly three places and everywhere else the system is deterministic (the ledger, the Merkle tree, the gate, Cedar, the witness, the generator's scripted scenarios, the explorer itself):
1. the **clinic decision-support agent** (hippagrchealthcare) and 2. the **Entropa audit-explainer** (entropa) on **AWS Nova Lite** through Amazon Bedrock (Guardrails and a human gate on the clinic side; AgentCore Runtime and Gateway only where they earn their place, ARCHITECTURE-AWS-SHOWCASE.md), and
3. the **bank fraud-triage agent** (bigironbank) on **GCP Gemini Flash** through Vertex AI on Cloud Run in `entropa-testnet`.
One provider-neutral agent interface sits in front of both clouds, so either cloud can take over any of the three agents, and every model call produces the same data-minimal signed `agent.invocation` event (hashes, counts, ids; never prompts or answers). Until those agents are deployed (S11), the generator records `provider: fake` events for them, so the explorer never claims a model call that did not happen.

## 4. The public event (data-minimal, strict, nothing free-form)
One JSON object per ledger record (record format v2, docs/adr/0011). Fields: `v`, `kind`, `tenant`, `actor` (a **public role handle** such as `builder-agent`, section 8, never an internal name), `ts`, `subject_hash`, `label_code`,
`decision`, `reason_code`, `policy_set_hash`, `approval_ref`, `agent` (provider, model id, token counts, cost in micro-dollars, never prompts or answers), `synthetic` (always `true`
until a real deployment exists), `sig` (ML-DSA signature of the actor). **No free text and no user-supplied strings are ever stored or rendered**: every
string is a hash, an id, a time, or a code from a closed list the front end maps to words ("fraud triage: hold proposed"), so event fields cannot carry personal data or markup.
Kinds: `agent.invocation` (S11), `policy.decision` (S4), `approval.request|approve|deny|consume` (S3), `witness.cosign` (S5), `directory.actor` (identities), `tx.screened` (a synthetic transaction decision).
Tenants: `entropa`, `bigironbank`, `hippagrchealthcare`. Ledger size at one event a minute is about 43,000 events a month at under 1 KB each, so about 40 MB a month.

## 5. The read API (GET only, JSON, public, CORS `*`, no cookies)
| Endpoint | Returns |
|---|---|
| `GET /api/head` | latest checkpoint, its witness statements, log public key fingerprint (short cache, 15 s) |
| `GET /api/checkpoints?limit&cursor` | checkpoint history |
| `GET /api/records?tenant&actor&kind&cursor&limit` | pages of events (max 100), newest first, with index |
| `GET /api/records/{index}` | one event with its record bytes (hex) |
| `GET /api/receipts/{index}?size=` | receipt: record, audit path, the checkpoint it is bound to (RFC 6962/9162 bound to index and size, ADR 0016) |
| `GET /api/consistency?old=&new=` | consistency proof between two sizes |
| `GET /api/witnesses?size=` | witness statements for a size |
| `GET /api/actors`, `GET /api/actors/{id}` | identity pages data (section 8) |
| `GET /api/feeds/{tenant}` | the tenant's recent events and counters |
| `GET /api/healthz` | liveness |
Contract (same discipline as the MCP server, ARCHITECTURE-MCP): strict query validation (known parameters only, integer bounds, closed value lists), hard response
size cap (256 KiB), a typed error JSON `{ "error": code }` with the right status and **never an echo of the input**, a per-IP token bucket (60 requests a minute, bursts of 20) in memory plus Cloud Run `max-instances 3` and `concurrency 80`
as the cost ceiling, `Cache-Control: public, max-age=31536000, immutable` for anything addressed by index or size and `max-age=15` for `head`. No endpoint accepts a body.

## 6. The synthetic AI-decisions generator
A Cloud Run Job, run every 10 minutes by Cloud Scheduler, is the only writer. Each run produces a small batch of **scripted synthetic scenarios** from a seeded, deterministic generator:
- `bigironbank`: a synthetic transaction is screened by a stub agent (or by Nova Lite once S11 is live), the agent proposes an action (hold, notify, freeze), the **real Cedar gate** (entropa-policy) decides, a hard-rule action needs an approval record, `orchestrator-agent` or `builder-agent` (agents with their own keys) approve or deny, and the `human-principal`'s `direction` approvals are attested by `orchestrator-agent`.
- `hippagrchealthcare`: a synthetic case summary is "reviewed": agent suggestion, guardrail result code, human gate, release.
- `entropa`: the audit-explainer answers (hash of the question, receipt ids it cited, verification result), plus system events (checkpoints, witness cosigns).
All records are signed by the acting actor's key, appended in order, then a checkpoint is signed. Everything the explorer shows is therefore produced by the same code paths the real system uses; the data is labelled synthetic in the page and in every event.
The generator can run without AWS (stub agent) so the explorer works even when the AWS credit ends.

## 7. Verification in the browser (the point of the whole thing)
| Option | What it is | Trust | Cost |
|---|---|---|---|
| **A (recommended)** | `entropa-core` and `entropa-witness` compiled to WebAssembly (a small `entropa-verify-wasm` crate, pinned toolchain, hash of the `.wasm` published in the repo) | the same code as the server; verified by the user's browser | one extra crate; ML-DSA-65 verify in WASM is fast |
| B (cross-check, later) | an independent JS verifier built on a different ML-DSA library plus our own Merkle code | a second implementation: disagreement is a bug alert | more code to maintain |
| C | server-side verify with an explicit trust note | trusts our server | none (rejected as the default) |
The page shows, step by step with a small animation of the Merkle path: (1) the record bytes decode as record v2; (2) the leaf hash; (3) the audit path to the root; (4) the checkpoint signature under the log key; (5) the checkpoint is consistent with a checkpoint the user saved earlier ("pin this head") ; (6) the witness statement signatures; (7) the actor's event signature and the actor's place in the signed directory (attestation chain).
**Trust note shown next to every "verified":** a key served by the same server proves nothing by itself. The page prints the log key fingerprint and tells the user to compare it with the fingerprint published in the repository and on a second channel (a DNS TXT record or the GitHub README, when the owner approves publishing). "Verified" means the maths check out against the key you compared, nothing more. A **"verify offline"** panel gives the exact command for the Rust verifier, so a sceptic never needs the page's code.

## 8. Identity pages
**Public naming rule (standing rule from the project owner, 2026-10-21): no public page, API field, event, key label or file name shows an internal name.** Actors have **role-based public handles**, each with its public key fingerprint:
`human-principal` (the accountable human; attested by `orchestrator-agent` until it holds a key of its own; the page states that the attestation opens `direction` only), `orchestrator-agent` (reviews and approves), `builder-agent` (writes and tests code), `operator-agent` (added when it exists), the system actors `log-signer`, `generator`, `witness-azure`, `cosigner-aws-kms`, and per tenant the site agents `agent-entropa`, `agent-bigironbank`, `agent-hippagrchealthcare`. The mapping from handles to team members lives only in the private project documents, never in this repository's public outputs, the ledger, the generated bundle or the website. One page per handle from the signed actor directory (docs/ARCHITECTURE-APPROVALS.md). Each shows: role, public key fingerprint, status (active/revoked at index N), what it may approve, counts, its latest events and every approval it gave or received, with verify buttons. No avatars, no personal data. A test (S7b) scans the exported bundle and the front-end sources for any internal name and fails if one appears.

## 9. Look and feel: the "ledger" look (distinctive, polished, accessible)
Direction (D5): a **logbook** rather than a dashboard. Warm paper-and-ink light theme with a true dark theme, serif display type for headings and a monospace face for hashes and indices, ruled lines, margin annotations for verification steps, numbered entries like pages of a logbook (neutral wording on the page: no film or series references, no internal names); restrained colour: one ink colour, one accent for "verified", one for "unverified/warning". No gradient orbs, no glassmorphism, no stock icons. Motion: only the Merkle-path walk and a subtle new-entry fade, off under `prefers-reduced-motion`. Layout: `Ledger` (live feed with filters), `Record` (the verify walk-through), `Actors`, three site pages, `Witnesses`, `Verify yourself`, `About and limits`. Responsive from 360 px, WCAG 2.2 AA contrast, keyboard navigable, no web fonts from third parties (self-hosted, subset), total first-load under 150 KB plus the WASM (lazy-loaded when the user presses Verify), no analytics, no cookies, strict CSP (`default-src 'self'`; `wasm-unsafe-eval` only for the verifier).

## 10. Threats (short)
| Threat | Mitigation |
|---|---|
| Our server lies (fake record or key) | in-browser verification, fingerprint comparison, witness cross-check, offline verifier |
| Old receipt replayed as current | the UI shows the checkpoint size and age of every proof and the `head` freshness; "pin this head" for consistency |
| XSS through event content | no free text exists; closed code lists; everything escaped; strict CSP |
| Scraping / cost abuse | CDN caching, immutable responses, rate limit, max instances 3, budget alert; no expensive endpoint |
| Split view by the log | witness statements and consistency from a pinned head (the witness design, ARCHITECTURE-WITNESS) |
| Key compromise of a demo actor | demo keys only sign synthetic events; rotation by directory records; the page shows revocations |
| Supply chain of the WASM | pinned toolchain, `cargo build --locked`, hash published, SRI on all script and wasm files |
| Personal data entering | impossible by schema: nothing user-supplied is accepted anywhere |

## 11. Hosting and price (GCP project entropa-testnet; price first)
**Price caveat:** Google's pricing pages render client-side and could not be read as text here, and the Cloud Billing Catalog API needs an API key (the owner's call). The figures below are Tier 1 list prices from training knowledge,
**unverified**; read the exact SKUs from the console pricing calculator before S7g. The forecast has wide margins.
| Service | Unit price (unverified) | Free tier (unverified) | Our use per month | Cost |
|---|---|---|---|---|
| Cloud Run (request-based) | $0.000024 per vCPU-s, $0.0000025 per GiB-s, $0.40 per M requests | 180,000 vCPU-s, 360,000 GiB-s, 2M requests | read API 300,000 requests x 0.1 s x 0.5 vCPU = 15,000 vCPU-s and 15,000 GiB-s; generator 4,320 runs x 20 s x 1 vCPU / 1 GiB = 86,400 vCPU-s and GiB-s | inside the free tier: $0.00 |
| Firebase Hosting (Blaze) | $0.026 per GB stored beyond 10 GB, $0.15 per GB egress beyond 360 MB a day | 10 GB, 360 MB a day | a few MB stored, mostly CDN hits | $0.00 |
| Cloud Storage standard | about $0.020 per GB-month | small free amount in some regions | about 40 MB a month growth, 0.5 GB in a year | under $0.02 |
| Secret Manager | about $0.06 per active secret version-month | 6 versions | 6 secrets (log key, 4 actor keys, generator) | about $0.36 |
| Cloud Scheduler | $0.10 per job-month | 3 jobs | 1 job | $0.00 |
| Artifact Registry | about $0.10 per GB-month | 0.5 GB | one image under 0.3 GB | $0.00 |
| Cloud Build | per build minute | free minutes | a few builds | $0.00 |
**Forecast: about $0.4 to $1 a month; idle cost about $0.4 (the secrets).** A 100x traffic spike is capped by the rate limit, `max-instances 3` and the CDN; worst case about $10 a month, so a **$10 budget alert** is set before deploy (alerts only).
Everything is on the GCP credit (about $1,290, to about Jul 2027), so the explorer can stay up long after AWS and Azure close. IaC: Terraform/OpenTofu or `gcloud` scripts in `infra/gcp/explorer/` (D4), tags/labels `project=entropa`.
**Teardown (the owner runs it; an agent deletes nothing):**
```
gcloud run services delete explorer-api --project entropa-testnet --region <region>
gcloud run jobs delete generator --project entropa-testnet --region <region>
gcloud scheduler jobs delete generator-tick --project entropa-testnet --location <region>
gcloud storage rm -r gs://<ledger-bucket>            # only after the evidence bundle is exported
gcloud secrets delete <name> --project entropa-testnet   # per secret
firebase hosting:disable --site <site>                # or roll back to the previous release
```
Rollback of the web cutover is one command: `firebase hosting:rollback` to the previous release (the old pages stay in the release history).

## 12. Migration of the existing website/ copy (marketing and legal exceptions)
Nothing is deleted. "Retire" means: replaced at its URL by the new page or a short "retired" notice, and the old file moved under `website/archive/` until the owner gives the delete word.
| File | Today | Action | Who decides |
|---|---|---|---|
| `public-main/index.html` | AML/KYC bank marketing, pricing and "$0.01 per attestation" claims, Stripe/FAQ JSON-LD, dead `/signup` links, examiner/BSA language | **Rewrite** as the explorer home (new copy: what the ledger is, what it proves, what it does not); remove every pricing, billing and compliance claim | the owner approves the text |
| `trust.html`, `sla.html`, `glossary.html` | trust, SLA and compliance-flavoured copy | **Rewrite** (trust -> "About and limits"; sla -> retire (there is no service level for a demo); glossary -> keep and trim the compliance entries) | the owner |
| `terms.html`, `privacy.html`, `contact.html` | partner/API/billing terms, Stripe, signup | **Rewrite minimal**: no accounts, no personal data collected, synthetic data only, contact by email only | the owner (legal text) |
| `hire.html`, `resume.html` | personal and career copy; mentions Stripe, signup and compliance | **Keep**, with only the stale product claims corrected | the owner |
| `dashboard.html`, `demo/dashboard.html`, `dashboard/explorer.html` | partner login dashboard and its explorer | **Retire** (replaced by the new explorer; the login API is gone) | the owner |
| `public-scryon/*` and Cloud Run `entropa-scryon` | legacy demo explorer + live feed `api.entropa.space/demo/feed` | **Replace** by the new explorer; run both in parallel, cut over, keep the old service for one rollback window; its deletion (and the Java GKE shutdown) are separate the owner decisions | the owner |
| `sitemap.xml`, `robots.txt`, `llms.txt` | list old pages; llms.txt describes a metered paid API | **Rewrite** to the new pages and the honest description | the owner |
Order: build on a Firebase Hosting **preview channel** (free, temporary URL), review, then cutover with the rollback above. No claim about regulation, certification or performance goes live without a source in the repo.

## 13. Stages (each its own branch, test-first, priced again)
S7b `explorer-api` crate stubs + red tests (contract, validation, rate limit, caching headers, error contract, golden JSON) / S7c implement + fuzz + mutation / S7d `entropa-verify-wasm` + test vectors shared with the Rust verifier / S7e static front end (no framework build step, or a minimal one) with accessibility and size tests / S7f generator job (deterministic seeds, golden scenarios) / S7g deploy to a preview and the first priced `entropa-testnet` resources (the owner's go) / S7h cutover and Scryon parallel run / S7i website copy migration.

## 14. Honest limits
- It shows synthetic data. "Verified" proves the maths against a key you compared, not that an AI decision was right, and not that the records are complete: a log can omit records, and a witness only constrains what it was shown.
- One log key, one generator, a few witnesses: a demonstration of the method, not a production audit service. No regulatory or compliance claim.
- Price figures for GCP are unverified until read from the console; the forecast has margins for that.
- Browser verification trusts the verifier code you load; the offline command and the published `.wasm` hash are the way out of that circle.

## 15. Decisions (answered 2026-10-21 by the project owner, D5 and D8 with the owner)
- **D1 Verifier:** WASM from entropa-core now, an independent JS verifier as a cross-check later. **Yes.**
- **D2 Hosting:** Firebase Hosting + Cloud Run + GCS as designed. **Yes.**
- **D3 Log key:** a software ML-DSA demo key in Secret Manager now, **plus an AWS KMS ML_DSA_65 co-signature on checkpoints while the AWS credit lasts** (the live KMS path) **and the Azure witness statement**. The explorer must keep working after those clouds lapse: a missing co-signature is shown as "cosigner offline", never as an error, and verification states exactly which signatures were present.
- **D4 IaC:** OpenTofu, run inside the dev container (no host install).
- **D5 Look:** the logbook look is the default with neutral names on the page (no series wording, no internal names); the owner decides the final look.
- **D6 Domains:** `explorer.entropa.space`; `scryon.entropa.space` redirects during the parallel run.
- **D7 Copy:** the author drafts the new home, terms and privacy text; the owner approves.
- **D8 Fingerprint channel:** the owner publishes the log key fingerprint later (second channel).
- **D9 Retention:** keep forever, with a yearly snapshot note.
- **D10 Real data:** synthetic only; any real deployment is a separate decision with its own review.

## 16. Service eligibility (standing rule, 2026-10-21)
Cloud-service eligibility note (checked 2026-10-21; re-check before adding a service and quarterly). For this design: **Firebase Hosting is not on Google's covered list, so it serves only the static public synthetic front end and the WASM verifier; nothing that touches PHI-equivalent data is served from it.** The read API on Cloud Run and the ledger in Cloud Storage are covered products. The ledger, the bundle and every API response are closed-code, data-minimal and carry no PHI-equivalent value (P0; canaries are scanned for). Cloud Scheduler, Secret Manager, Cloud KMS and Cloud Logging are on Google's covered list; keep PHI-equivalent values out of labels, metadata and logs. In the `entropa-testnet` project, unsupported services are disabled if the project ever holds PHI-equivalent data (the old GKE cluster's decommission is a separate decision needing the owner's exact word).
