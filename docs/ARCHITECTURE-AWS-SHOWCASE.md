# ARCHITECTURE-AWS-SHOWCASE: agentic AI on AWS (Bedrock) and GCP (Gemini) for all three sites (stage S11a, design only)

Status: design for review. **No AWS or GCP resource is created by this document.** Written 2026-10-21 on branch
`rerust-s11a-aws-showcase-arch` (from `rerust-int-s4f`). Nothing here is billable until the owner says go with the price restated.
Hard rules carried over: **never AWS Organizations, account changes, plan upgrades or "convert to paid"**; synthetic data only;
no secrets in the repo; every resource tagged `project=entropa`; teardown commands are run by the owner, an agent deletes nothing.

> **Revision 2026-10-21 (the owner's decisions, relayed by the reviewer):** the S11b probe ran: two successful Converse calls to Amazon Nova Lite (HTTP 200, about $0.0000022 each). **Static rules: one provider per cloud. AWS = the Amazon Nova family (Nova Lite is the default, Nova Pro the step-up for flagged hard cases); GCP = Gemini Flash; Azure = no LLM (the Azure witness is deterministic code); no other providers.** Claude on Bedrock is not planned; Nova Lite and Nova Pro are the AWS models, Gemini the second provider. Sections 4.1, 7, 8, 9 and 13 below are revised accordingly.

## 1. Goal and constraints
The owner's direction (2026-10-21): show the largest SAP-C03 competencies on all three sites (entropa.space, bigironbank.online,
hippagrchealthcare.site with ~/clinic-ops), heavy on agentic AI and Amazon Bedrock, on the AWS credit plus the GCP credit, so the sites keep
running for a few months while the owner is being hired. The owner accepts spending up to about **$180 of the $198 AWS credit**.

| Fact | Value | Source / status |
|---|---|---|
| AWS credit | $198 (the owner's statement) | taken as fact |
| AWS account plan | Free plan, closes at about 6 months (about April 2027) or when credits run out; reopening needs an upgrade, which is forbidden | docs/SAP-C03-RESEARCH.md (AWS What's New Jul 2025), conflicting secondary sources: **plan for about 6 months, not permanent hosting** |
| GCP | about $1,290 grant, expires about Jul 2027, project `entropa-testnet` (the one GCP project) | the owner's figure; GCP is the permanent home for static pages |
| Azure | pot B ends about Nov 17 2026 | S5 witness, separate design |
| Credit covers Amazon Nova on Bedrock? | **UNVERIFIED** until Billing shows a credit on the Nova line | tested first, section 9 |

Consequence: everything is infrastructure as code plus an evidence bundle, runs scale-to-zero, and degrades to a static "agent offline"
page when AWS closes. Permanent, always-on parts (static pages) stay on GCP and free tiers.

## 2. SAP-C03 competencies mapped to one concrete component per site
The official exam guide is published on 2026-10-27; this map follows AWS's announcement (docs/SAP-C03-RESEARCH.md) and is re-checked that day.
| Competency (AWS-named) | Component | Site |
|---|---|---|
| Amazon Bedrock integrations; RAG | Audit-explainer agent: retrieval over signed log records, answers cite receipt ids a user can verify | entropa.space |
| AgentCore agent architectures (Runtime, Gateway, Identity, Policy, Memory, Observability) | The read-only entropa-mcp tools exposed through **AgentCore Gateway** to the explainer, hosted on **AgentCore Runtime**; Cedar policy (our S4 gate) beside AgentCore Policy | entropa.space |
| Bedrock Guardrails; human-oversight workflows | Decision-support agent on synthetic patients: Guardrails on its output, Step Functions wait-for-callback human gate, approval written to the ledger | hippagrchealthcare.site / clinic-ops |
| Agentic AI behind a policy gate | Fraud-triage agent on synthetic transactions: every action goes through the Cedar gate and the approvals ledger before it "executes" | bigironbank.online |
| Post-quantum cryptography (KMS ML-DSA) | Checkpoints signed by the existing KMS `ML_DSA_65` key; per-actor ML-DSA signatures on agent events | all |
| Serverless, event-driven, Step Functions | API Gateway HTTP API, Lambda arm64, DynamoDB on-demand, Step Functions, EventBridge | all |
| Multi-tenant architecture | One stack, three tenants: separate DynamoDB partitions, separate IAM roles, separate Guardrail configs, per-tenant tags and cost lines | all |
| Cost optimization | Per-request unit costs, scale-to-zero, Graviton, forecast vs actual per resource, budget alarms (section 8) | all |
| Resilience / DR | Checkpoint replica in S3 (versioned), documented RTO/RPO, runbook; FIS and Resilience Hub as **design-only** unless priced separately | design |
| Observability and AI/ML metrics | CloudWatch logs (short retention), alarms, token and cost metrics per tenant | all |
| Multi-account / governance | **Design documents and diagrams only**. We do not create AWS Organizations (rule). | design |
| Migration and modernisation | The Java-on-GKE to Rust story and the cross-cloud agent routing, as a case study | write-up |

## 3. One provider-neutral agent interface, one ledger event
A small Rust crate (`entropa-agent`, stage S11c) defines the seam so Bedrock and Gemini are interchangeable and the Entropa ledger records
identical, data-minimal events either way:
```
trait AgentModel { fn invoke(&self, req: &ModelRequest) -> Result<ModelResponse, AgentError>; }   // exactly three implementations: AwsNova (model tier parameter Lite or Pro), GcpGemini, Fake (tests and demo); no other provider
ModelRequest  { tenant, task_kind, messages (never logged), max_output_tokens, guard_profile }
ModelResponse { text (never logged), input_tokens, output_tokens, finish_reason, guard_result }
```
Ledger record `agent.invocation` (strict decoder, canonical JSON with sorted keys, signed with the acting actor's ML-DSA key, same pattern as
approvals and policy decisions): `v, type, actor, ts, tenant, provider ("bedrock"|"vertex"|"fake"), model_id, request_hash, response_hash,
input_tokens, output_tokens, cost_micro_usd, guard_result, policy_set_hash, decision_ref, approval_ref, sig`. Prompts and answers are
hashed, never stored; only hashes, counts, ids and decisions reach the log. A router picks the provider per task by a published rule
(cheapest adequate model, quota, availability) and records why. Every agent action that changes something goes: Cedar gate (S4) ->
approvals gate (S3) -> action; failure of either is a deny. Per-actor keys: the owner, the reviewer, the author each have an Entropa identity (the owner
attested by the reviewer until he holds a key; Sulu later); the agents get their own actor identities, listed in the signed directory.

## 4. The three agentic pieces
1. **entropa.space: audit-explainer.** Reads only the read-only MCP tools (`log_head`, `verify_checkpoint`, `verify_receipt`, `list_records`,
   `explain_proof`), exposed through AgentCore Gateway; answers questions about the public audit log and cites receipt ids; every answer is
   re-checkable by the user with the verifier. Cannot write to the log except its own `agent.invocation` events. Hosted on AgentCore Runtime
   (earns its place: session isolation, consumption billing, Gateway as the tool boundary).
2. **hippagrchealthcare.site: decision-support agent (synthetic data only).** Triage-style suggestions on invented cases. Bedrock Guardrails
   (content, denied topics such as "definitive diagnosis", PII filter) on output; a Step Functions human gate must produce an approval record
   before a suggestion is shown as "reviewed"; no real patient data, ever; no medical-compliance claim.
3. **bigironbank.online: fraud-triage agent (synthetic transactions).** Scores and explains; proposed actions (hold, notify) are Cedar
   requests; hard-rule actions need an approval record; the ledger holds the proposal, the policy decision and the approval, anchored by
   chain-head hash (S10b).
Strands Agents SDK is a fit for the tool-loop in pieces 1 and 3 if its runtime on Lambda/AgentCore is confirmed; otherwise a thin Rust or
Python loop over the Converse API does the same job. AgentCore Memory is used only if a session memory is needed (short-term events are free per the price file).

## 4.1 Placement of the three agents across the clouds (DECIDED by the owner, 2026-10-21)
- **Clinic decision-support agent** and **Entropa audit-explainer**: AWS, **Amazon Nova Lite** on Bedrock; Guardrails and the Step Functions human gate on the clinic side; AgentCore Runtime and Gateway for the explainer only where they earn their place.
- **Bank fraud-triage agent**: **GCP, Gemini Flash** on Vertex AI, run from Cloud Run in `entropa-testnet`, behind the Cedar gate and the approvals ledger.
- **LLMs only in these three places; everything else is deterministic.** One provider-neutral interface, so either cloud can take over any agent (the router records the reason), and the same data-minimal signed `agent.invocation` event whichever cloud answered.
- **Effect on the AWS forecast (section 8):** that table assumed all three tenants on Nova. With the bank on Gemini the AWS model lines fall by a third: 5,400 Lite calls x $0.00030 = $1.62 and 600 Pro calls x $0.00400 = $2.40 (instead of $2.43 and $3.60), Guardrails (clinic only), AgentCore, CloudWatch and KMS unchanged, so the AWS base case is **about $12.4 a month** (was $14.4). The bank's 3,000 calls a month move to the GCP credit: at the unverified introductory Gemini Flash price of $0.75 / $3.75 per 1M tokens that is 3,000 x (3,000 x $0.75 + 500 x $3.75) / 1M = about $12.4 a month (about $0.9 at an unverified Flash-Lite price of $0.30 / $2.50 per 1M); the exact Vertex SKU prices must still be read before S11h. **Updated 2026-10-21 (docs/ARCHITECTURE-MEMORY.md section 6):** at Gemini 2.5 Flash's $0.30 / $2.50 per 1M tokens (search-result summary of Google's pricing page) the same 3,000 calls cost 3,000 x (3,000 x $0.30 + 500 x $2.50) / 1M = **about $6.45 a month**; at Gemini 2.5 Flash-Lite ($0.10 / $0.40, the owner's paste, unconfirmed) about $1.50; **the owner decided (2026-10-21) to run the newest generally-available Gemini Flash** (expected 3.8 Flash: $0.75 / $3.75 per 1M through 2026-12-31, read on the Gemini Developer API pricing page; Vertex SKU price and GA status UNVERIFIED): 3,000 x (3,000 x $0.75 + 500 x $3.75) / 1M = **about $12.4 a month**, and **about $24.8 from 2027-01-01** at $1.50 / $7.50; 2.5 Flash ($6.45) is the confirmed fallback.

## 5. Architecture (all serverless, scale to zero)
```
 site (static, GCP/Firebase Hosting) --HTTPS--> API Gateway (HTTP API) --> Lambda arm64 "agent-router"
                                                         |                     |  tenant, task, guard profile
                  Step Functions (human gate, SNS email) <-+                     +--> Bedrock Converse (Nova Lite default, Nova Pro for flagged hard cases) [+ Guardrails]
                                                         |                     +--> Vertex Gemini via Cloud Run in entropa-testnet (GCP credit), called with a federated identity
                                  DynamoDB (state, idempotency)                  +--> entropa-policy (Cedar) + approvals -> ledger (S3 + signed checkpoints, KMS ML-DSA-65)
                                  S3 (evidence, checkpoint replica, versioned)   +--> AgentCore Gateway -> entropa-mcp tools (explainer only)
 EventBridge schedule -> cost agent (read-only) -> signed finding record; CloudWatch logs (7 days), alarms; Budgets alerts
```
No VPC, NAT gateway, load balancer or always-on compute (those are the usual hidden costs). Secrets: AWS SSM Parameter Store (standard tier is free)
or Secrets Manager only if a rotation story is needed (priced then). Cross-cloud: the Gemini path runs inside GCP (Cloud Run, scale to zero,
GCP credit) and is called from AWS with a short-lived federated token, so no long-lived key crosses clouds.

## 6. Infrastructure as code, tags, budgets
CloudFormation (SAM) for AWS, because it needs no extra toolchain, it is what the exam names, and Rust Lambdas deploy with `cargo lambda`
(D3). GCP: a single `gcloud run deploy` script or OpenTofu, in `infra/gcp/`. All resources tagged `project=entropa`, `site=<tenant>`, `stage=S11x`.
Change sets / `what-if` are reviewed before every deploy (free). Budgets: the existing `capstone-40` has alerts; add cumulative thresholds
$60, $120, $160 (alerts only; the owner's call to change a budget, no billing or plan change). A kill switch: an SSM flag the router checks, plus
`aws lambda put-function-concurrency --function-name <name> --reserved-concurrent-executions 0` (the owner runs it).

## 7. Unit costs (read from the official price sources, us-west-2, 2026-10-21)
AWS: the public Price List bulk files (`pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<offer>/current/...`), on-demand, no credentials used.
| Item | Unit cost |
|---|---|
| **Amazon Nova Lite (the default)** | **$0.06 / 1M input tokens, $0.24 / 1M output tokens** (AWS Price List, us-west-2) |
| **Amazon Nova Pro (step-up; about 13x Lite)** | **$0.80 / 1M input, $3.20 / 1M output** |
| Amazon Nova Micro and Nova 2.0 Lite (for reference) | Micro $0.035 / $0.14 per 1M; Nova 2.0 Lite $0.30 / $2.50 |
| Bedrock Guardrails | content filter $0.15, denied topics $0.15, ML PII filter $0.10, contextual grounding $0.10 per 1,000 text units (1 unit = up to 1,000 characters); regex words/PII free |
| AgentCore Runtime (consumption) | $0.0895 per vCPU-hour + $0.00945 per GB-hour, active time only |
| AgentCore Gateway | $0.000005 per tool invocation ($5 per million); search $0.000025; indexing $0.0002 per tool-month |
| AgentCore Memory | short-term events $0.00; long-term storage $0.00025 to $0.00075 per memory-month; retrieval $0.0005 each |
| AgentCore Identity, Policy, Observability | **no separate meter found in the price file: confirm before relying on them being free** |
| Lambda arm64 | $0.20 per 1M requests, $0.0000133334 per GB-second (first 1M requests and 400,000 GB-s a month free tier) |
| API Gateway HTTP API | $1.00 per 1M requests |
| DynamoDB on-demand | $0.625 per 1M writes, $0.125 per 1M reads, first 25 GB free |
| Step Functions standard | $0.000025 per state transition (first 4,000 free) |
| S3 standard | $0.023 per GB-month, $0.005 per 1,000 PUT, $0.0004 per 1,000 GET |
| CloudWatch | logs ingest $0.50 per GB, alarm $0.10 per month, custom metrics from $0.30 per metric-month |
| KMS | $1.00 per key-month (existing key), asymmetric requests $0.15 per 10,000 (ML-DSA rate to confirm, S1 ledger) |
GCP: Vertex AI Gemini is on the Google pricing page, which could not be read as text in this session (it renders client-side). What was found:
the page's own introductory notice for Gemini 3.7 Flash and 3.6 Flash, $0.75 / $3.75 per 1M tokens input / output through 2026-12-31 and
$1.50 / $7.50 after (via search snippet of the official page); Flash-Lite figures only from third-party calculators ($0.25 to $0.30 input,
$1.50 to $2.50 output per 1M) and **unverified**. Before S11h the owner or I read the exact SKU prices from the Cloud Billing catalog or the
console pricing calculator for `entropa-testnet`. Reading: Nova Lite ($0.06 / $0.24 per 1M) is more than ten times cheaper per token than Gemini Flash at the listed prices, so Gemini is used where the placement decision puts it (the bank agent, on the GCP credit) or where Lite cannot do the task.

## 8. Run-rate forecast (the whole showcase), recomputed for Nova
Assumptions per month (unchanged): 3 tenants x 100 agent calls a day = 9,000 calls; each call 3,000 input and 500 output tokens;
**90% Nova Lite and 10% Nova Pro**; Guardrails on the clinic tenant only (3,000 calls, about 3 text units each, $0.15 + $0.15 + $0.10 =
$0.40 per 1,000 units); AgentCore Runtime for the explainer only (3,000 sessions of 10 s at 1 vCPU / 2 GB, 6 gateway calls each); checkpoint signing once a minute.
Formula: model cost per call = (input tokens x input price + output tokens x output price) / 1,000,000.
| Line | Calculation | $ per month |
|---|---|---|
| Nova Lite | per call (3,000 x $0.06 + 500 x $0.24) / 1M = $0.00030; x 8,100 calls | 2.43 |
| Nova Pro | per call (3,000 x $0.80 + 500 x $3.20) / 1M = $0.00400; x 900 calls | 3.60 |
| Guardrails (clinic) | 3,000 calls x 3 units x $0.40 / 1,000 | 3.60 |
| AgentCore Runtime | 3,000 x (10 s x 1 vCPU x $0.0895 + 10 s x 2 GB x $0.00945) / 3,600 | 0.92 |
| AgentCore Gateway | 18,000 invocations x $0.000005 | 0.09 |
| Lambda + API Gateway + DynamoDB + S3 + Step Functions | well inside free tiers or cents | 0.60 |
| CloudWatch (1 GB logs, 10 alarms) | $0.50 + $1.00 | 1.50 |
| KMS (1 key, 43,200 signing requests) | $1.00 + 43,200 / 10,000 x $0.15 | 1.65 |
| **Total (base)** | | **about $14.4** |
**Idle cost** (no traffic) is unchanged: the KMS key, alarms and a few cents of storage, **about $2 to $3 a month**.
**Duration inside $180:** 180 / 14.4 = about 12.5 months, so the plan is limited by the AWS Free plan lifetime (about 6 months), not by the credit:
4 months is about $58 and 6 months about $86, leaving about $94 to $122 for exam labs and reserve.
**Heavy case** (3x traffic = 27,000 calls, 30% Nova Pro, Guardrails on every tenant): Nova Lite 18,900 x $0.00030 = $5.67, Nova Pro 8,100 x $0.00400 =
$32.40, Guardrails 27,000 x 3 units x $0.40 / 1,000 = $32.40, plus about $5 for the rest: **about $75.5 a month**, which exhausts $180 in about 2.4 months.
Two lessons: Guardrails cost as much as the model at this size (apply them to the clinic output only), and Pro, not Lite, is where cost can run away (Lite is the default, Pro the exception): the cost agent routes a call to Pro only when it is flagged as a hard case (a Lite failure on the S11e checks or an explicit flag) and only while the month's spend is inside the cap.
**Cap re-derived:** 4 months inside $180 allows $45 a month. The base case uses about 32% of that and the heavy case about 168%, so the $45 monthly cap
stays, enforced by the cost agent, with cumulative alerts at $60 / $120 / $160.
Per-actor KMS keys would add $1 a month each, so demo actors use software ML-DSA keys in SSM SecureString and only the log signer uses KMS (D4).
These are forecasts; the actual comes from Cost Explorer / billing with variance explained, recorded in docs/FINOPS-LEDGER.md as forecast first, actual second.

### 8.1 What Nova Lite can and cannot do for the agent pieces
From AWS's Nova Lite model card and the Converse API guide (via search; the per-model tool-use matrix was not found on an AWS page, so confirm in the first S11e test):
- Context window **300K tokens**; **maximum output 5K tokens** (model card). Enough for the explainer's retrieval answers and the triage explanations (we cap answers at about 500 tokens); not enough for long reports.
- Called through the **Converse API** with a system prompt, `maxTokens` and stop sequences; **tool use (function calling)** is a Converse feature that the Nova understanding models support, which is what the AgentCore Gateway tools and the Strands loop need. Unconfirmed: how reliably Lite follows multi-step tool plans; Pro is the step-up.
- Multimodal input (images, video) exists but the showcase uses text only.
- Not suited: very long contexts beyond 300K, long-form output beyond 5K tokens, and complex multi-tool reasoning where Lite fails the S11e checks.
**Where Gemini takes over** through the provider-neutral interface (section 3): a task that needs more than 300K tokens of context, output beyond 5K tokens, multimodal analysis, a Lite or Pro failure on the tool-use checks, or Nova quota or availability problems. The router records the reason in the `agent.invocation` event, so the ledger shows the same data-minimal fields either way.

### 8.2 Cost levels, routing and the cost agent (the owner's condition for keeping Nova Pro, 2026-10-21)
Nova Pro stays in the plan on one condition: **usage stays within the forecast range.** The levels below are **configuration values** (read by the cost agent and the router from configuration, never compiled-in constants), so the owner can change them without a code change.
| Level | Monthly AWS spend | What happens |
|---|---|---|
| **Forecast base** | about $14 (about $12.4 with the bank agent on Gemini) | normal; Lite default, Pro for flagged hard cases, at most about 10-15% of calls |
| **Acceptable range** | up to about $25 | normal operation |
| **Soft limit** | over about $25 | the cost agent **stops routing to Pro** (Lite and Gemini continue) and **alerts the owner** |
| **Hard cap** | $45 | **all AWS model calls pause** until the owner says go (resuming is a `spend` decision, a hard-rule class: the owner's own signed approval, never an attestation) |
| **Cumulative alerts** | $60 / $120 / $160 against the $180 budget | alerts to the owner |
Configuration keys (names are proposals): `forecast_base_usd` 14, `acceptable_max_usd` 25, `pro_stop_usd` 25, `hard_cap_usd` 45, `cumulative_alerts_usd` [60, 120, 160], `budget_usd` 180, `pro_target_share_pct` 10, `pro_max_share_pct` 15.
**The arithmetic** (per call: Lite $0.00030, Pro $0.00400 at 3,000 input / 500 output tokens; non-model lines: Guardrails 3.60 + AgentCore Runtime 0.92 + Gateway 0.09 + Lambda etc. 0.60 + CloudWatch 1.50 + KMS 1.65 = **$8.36** a month; 9,000 calls a month with all three tenants on AWS, 6,000 with the bank on Gemini):
| Case | Calls | Pro share | Model cost | Total a month | Level |
|---|---|---|---|---|---|
| All Lite | 9,000 | 0% | 9,000 x $0.00030 = $2.70 | $11.06 | below base |
| **Forecast base** | 9,000 | 10% | 8,100 x $0.00030 + 900 x $0.00400 = $2.43 + $3.60 = $6.03 | **$14.39** | base |
| Pro at its ceiling | 9,000 | 15% | 7,650 x $0.00030 + 1,350 x $0.00400 = $2.30 + $5.40 = $7.70 | $16.05 | acceptable |
| Bank on Gemini, base | 6,000 | 10% | 5,400 x $0.00030 + 600 x $0.00400 = $1.62 + $2.40 = $4.02 | $12.38 | base |
| Pro share that reaches the soft limit | 9,000 | about 42% | (25 - 8.36) / 9,000 = $0.00185 a call on average | $25.05 | soft limit |
| Double traffic, Pro 10% | 18,000 | 10% | Guardrails and AgentCore scale with traffic | about $25.0 | soft limit |
| Double traffic, Pro 15% | 18,000 | 15% | | about $28.4 | over: Pro stops |
| Triple traffic, Pro 10% / 15% | 27,000 | 10% / 15% | | about $35.7 / $40.7 | below the cap |
| Everything on Pro | 9,000 | 100% | 9,000 x $0.00400 = $36.00 | $44.36 | just under the cap |
| Earlier "heavy" case (3x traffic, 30% Pro, Guardrails on every tenant) | 27,000 | 30% | section 8 | about $75.5 | **hits the hard cap**: the pause protects the credit |
The multiples assume Guardrails stay on the clinic tenant only; with Guardrails on every tenant they add $21.6 more at triple traffic (27,000 x 3 units x $0.40 / 1,000 = $32.40 instead of $10.80). Reading: at the forecast traffic, Pro would have to carry about 42% of all calls to reach the soft limit and essentially every call to approach the cap, so the 10-15% rule is the real control, and the soft limit mostly guards against a traffic surge.
**Routing and attribution.** The router (section 3) picks a tier per call by the published rule: Lite by default; Pro only when the task is **flagged hard** (a Lite failure on the S11e checks, or an explicit flag) and the month is below the soft limit and Pro's share is below its ceiling; Gemini when the placement says so or Lite cannot do the task. **Every routing decision is a signed, data-minimal ledger event**: the `agent.invocation` record carries `tier` (lite, pro) and `route_reason` (a closed code: default, hard_case, lite_failed, over_soft_limit, over_cap_paused, quota, unavailable), so cost is attributable by tier and reason; no prompt or answer is stored.
**The cost agent** is read-only and signs findings (S11i); the router enforces. Its running total comes from the ledger (token counts x the configured prices, available immediately) and is reconciled daily against Cost Explorer, which lags by up to about a day. Crossing the soft limit writes a signed `cost.finding` that the router reads (Pro off) and alerts the owner; reaching the cap writes a second finding that pauses AWS model calls. Neither finding spends or deletes anything; resuming needs the owner's approval record (class `spend`). Both transitions are exercised in the kill-switch rehearsal of S11i.

## 9. First step: the tiny priced Bedrock probe (S11b): DONE
The probe (scripts/probe-bedrock.sh, runbook docs/runbooks/bedrock-probe.md) ran: **two successful Converse calls to `amazon.nova-lite-v1:0`**, HTTP 200, estimated about $0.0000022 each
(20 input and 3 output tokens at $0.06 / $0.24 per 1M). An earlier 403 is unexplained; the leading candidates are whitespace in the pasted environment values (now stripped by the script) or access propagation.
The script's SigV4 was verified against botocore, the AWS SDK reference, in 6 of 6 cases (docs/evidence/s11c-botocore-compare.txt).
**Billing check still pending (the open question that decides the branch below):** whether the credit applied, and under which service line (Amazon Bedrock or AWS Marketplace) the charge appears; to be read from Billing and Cost Explorer the next day and recorded in docs/FINOPS-LEDGER.md.
**Decision rule, kept and updated.** An unverified statement that AWS promotional credits cover Nova Lite has been relayed; treat it as unverified until the Billing page shows a credit on the Nova line.
- **Credit applied to the Nova line:** proceed with Nova Lite as the default as designed.
- **Credit NOT applied (the charge is paid by card or shows as due):** the AWS agent spend is out of pocket, so nothing beyond the probe is deployed on AWS until the owner decides. The showcase then runs on **Gemini on Vertex AI on the GCP credit** as the primary provider (through the same provider-neutral interface), the AWS side stays as design, the KMS signing key and its tiny cost are reviewed separately, and the $45 monthly cap is replaced by a the owner-set cap in real dollars (the base case would be about $14.4 a month, the heavy case about $75.5).

## 10. Staged build order (each billable stage priced again, the owner says go)
- **S11b** priced Bedrock test call: DONE (2 successful Nova Lite calls); billing check pending.
- **S11c** `entropa-agent` crate: provider-neutral trait, `agent.invocation` record, fake backend, red tests, golden vectors, fuzz, mutation. Local, $0.
- **S11d** CloudFormation/SAM stack and GCP script written and linted; change set reviewed; nothing deployed. $0.
- **S11e** deploy the entropa.space explainer (Lambda, API Gateway, DynamoDB, Gateway + Runtime); evidence captured. Priced.
- **S11f** clinic decision-support agent: Guardrails, Step Functions human gate, ledger. Priced.
- **S11g** bank fraud-triage agent: Cedar gate and approvals. Priced.
- **S11h** Vertex Gemini backend on Cloud Run in `entropa-testnet`; router with cost rule. GCP credit.
- **S11i** cost agent (read-only, signed findings), budgets at $60 / $120 / $160, kill switch rehearsal.
- **S11j** evidence bundle, runbook, teardown rehearsal; write-up for the site and book (exact limits, cost forecast vs actual).

## 11. Teardown (the owner runs it; nothing deleted by an agent)
```
aws cloudformation delete-stack --stack-name entropa-showcase --region us-west-2      # all stack resources
aws cloudformation wait stack-delete-complete --stack-name entropa-showcase --region us-west-2
gcloud run services delete <service> --project entropa-testnet --region <region>      # per Cloud Run service
```
Resources outside the stack (the KMS key, the budget, S3 buckets with retained evidence) are listed in the ledger with their own commands; the KMS key
deletion is a scheduled deletion with a waiting period. The deletion rules apply: the owner's exact word plus a standalone yes/no before any delete.

## 12. Honest limits
- The agents advise on **synthetic** data. The ledger proves who recorded what and that it was not changed; it does not prove an agent's answer is correct. No compliance claim of any kind (HIPAA, banking, SOC).
- Guardrails reduce risk; they do not make a model safe. The human gate and the Cedar gate are the control, and they fail closed.
- Prices change; every number above is dated 2026-10-21 and must be re-read before a deploy. AgentCore Identity/Policy/Observability costs and the Vertex Flash-Lite price are not confirmed.
- AWS may close the account at about six months; this design assumes that and ends in a static fallback, not a migration.
- The exam guide arrives 2026-10-27; the competency map is adjusted then.

## 13. Decisions for the reviewer and the owner
- **D1 Models (decided by the owner 2026-10-21, static rules revised the same day):** one provider per cloud. AWS = the Amazon Nova family: Nova Lite the default for the whole showcase, Nova Pro the step-up for hard cases (the cost agent routes to Pro only for flagged hard cases and only within the monthly cap); GCP = Gemini Flash, the second provider where quota or capability warrants; Azure = no LLM (the witness is deterministic code). The provider-neutral interface has exactly three implementations: `AwsNova` (tier Lite or Pro), `GcpGemini`, `Fake`. No other providers.
- **D2 AgentCore:** use Runtime + Gateway for the explainer only (where it earns its place); Memory/Identity/Policy only if their price is confirmed free or tiny.
- **D3 IaC:** CloudFormation/SAM (recommended) vs CDK.
- **D4 Keys:** KMS for the log signer only; demo actor keys as software ML-DSA in SSM SecureString.
- **D5 Strands SDK:** use if it runs on Lambda/AgentCore as documented; else a thin loop.
- **D6 Cap and levels:** monthly hard cap $45 (4 months inside $180) as before; the full level table (base about $14, acceptable to about $25, Pro off over about $25, all AWS model calls paused at $45, cumulative alerts $60 / $120 / $160) and its arithmetic are in section 8.2; base about $14.4 a month (32% of the cap), the earlier heavy case about $75.5 would hit the cap; enforced by the cost agent and the router, thresholds are configuration values.
- **D7 After AWS closes:** sites fall back to static pages on GCP; the agent endpoints return "agent offline", nothing else.
- **D8 GCP prices:** read the exact Vertex SKUs for `entropa-testnet` before S11h.

## 14. Service eligibility (standing rule, 2026-10-21)
Rule source and links: a project record (not published), "Standing rule: service eligibility for PHI-equivalent data" (checked 2026-10-21; re-check before adding a service and quarterly). For this design: Bedrock, AgentCore, KMS, Lambda, Step Functions, S3, DynamoDB, CloudWatch, SNS, CloudTrail, CloudFormation, API Gateway and Secrets Manager are on AWS's list; **the Nova models are not listed by name (only Nova Act is), so no PHI-equivalent text goes to Nova**: the agents receive closed-code, data-minimal inputs only until the owner and the reviewer confirm coverage with AWS. Guardrails and Knowledge Bases are Bedrock features and S3 Vectors a feature of S3 (parents listed, features not listed separately): treated as eligible features with a **"confirm" note** and closed-code corpora. EventBridge Scheduler is not listed separately (EventBridge is): no PHI-equivalent data in schedules. IAM is control plane only; Budgets is not listed and holds no ePHI. Prefer Secrets Manager over Systems Manager Parameter Store (partial coverage); the demo actor keys in section 8 (SSM SecureString) should move to Secrets Manager if this ever holds PHI-equivalent data.
