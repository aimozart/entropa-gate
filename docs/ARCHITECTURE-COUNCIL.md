# ARCHITECTURE-COUNCIL: the Decision Review Council with a Contestor (stage S12a, design only)

Status: DESIGN. No code, no cloud resource, nothing billable is created by this document. Branch `rerust-s12a-council-arch` (from the S7e line). Source of the plan: the owner's decision relayed by the project owner on 2026-10-21 (a project record (not published), S12 series, S12d decision memory). Every price below is either read from an official price file on 2026-10-21 (marked **[price file]**) or flagged **UNVERIFIED**. Token counts are stated assumptions, not measurements.

## 1. Purpose, and what the council is not
AI agents (the clinic decision-support agent, the audit-explainer, the bank fraud-triage agent) and the people around them make decisions that the ledger already records and the Cedar and approvals gates already constrain. Nothing yet **learns** from those decisions. The council is a weekly, evidence-based review loop: look at what was decided, challenge it, let the human decide what to change, change it through the existing gates, prove the change on recorded synthetic decisions, and record all of it as signed ledger events.

It is **not** an autonomous governor. Rules that never bend (from the plan, restated as testable requirements):
1. **The council proposes and never changes production by itself.** Every change goes through the approvals gate (ARCHITECTURE-APPROVALS) and, for policy, the Cedar gate (ARCHITECTURE-CEDAR). No quorum means no change.
2. **Nobody approves their own work.** The model that decided is never its own critic; the critic is never the contestor; the compiler of the packet cannot drop a finding about its own decisions (section 5).
3. **Hard-rule items are the human principal's alone** (`delete`, `spend`, `publish`, `credentials_change`, and anything billing). An attestation can never decide them (ARCHITECTURE-APPROVALS section 6). This makes the owner's own signing key a prerequisite (decision D3).
4. **Synthetic data only.** The council reviews decisions the generator made from scripted scenarios; there is no real patient or customer data anywhere in it.
5. **Public naming by role, never internal names.** New role handles: `critic-agent`, `contestor-agent` (and `scheduler` for the system trigger). Provider and model ids appear in events exactly as they already do in `agent.invocation`.
6. **A signature proves who recorded what, not that a judgment is correct.** A critic's finding or the human's decision is a recorded opinion. No compliance claim is made.

## 2. Roles
| Role | Who | Does | Cannot |
|---|---|---|---|
| **Human principal** (`human-principal`) | the owner | Decides every item (accept / reject / defer); sole authority for hard-rule items; opens triggered sessions | be replaced by an attestation on a hard-rule item |
| **Orchestrator** (`orchestrator-agent`) | AI | Verifies evidence references (deterministic code, no model) and drafts one recommendation per item; compiles the packet | drop, merge or reorder-away a finding; decide anything |
| **Critic** (`critic-agent`) | a model of **another provider** than the agent whose decision is reviewed (Gemini reviews Nova-based decisions and the reverse) | Submits findings, each citing evidence references | cite anything it was not shown; see outcomes before the decision it reviews was made (section 8, hindsight) |
| **Contestor** (`contestor-agent`) | a model of a **different family from the critic** | Argues against each finding (a rebuttal per finding), to prevent groupthink | approve, or change a finding |
| **Scheduler** (`scheduler`) | Cloud Scheduler or EventBridge Scheduler | Writes `session.opened` | do anything else |
| **Builder** (`builder-agent`) | AI | Turns accepted findings into a red test, a Cedar change request, or a lesson (always on its own branch, human-gated) | merge or deploy |

**Independence rule (code, not convention):** `family(critic) != family(deciding agent)` and `family(contestor) != family(critic)`. The decided model set has two families, one provider per cloud (the Amazon Nova family on AWS, Gemini Flash on GCP; no model on Azure), so a contestor of a Gemini critic is a Nova model and a contestor of a Nova critic is a Gemini model: the contestor of a finding against Nova-based decisions is therefore a Nova-family model, i.e. the same family as the agent under review. That is a known weakness (it may be inclined to defend its own family), stated in section 15 and covered by the planted-fault suite; a third family would remove it (D1). A reviewer that violates the rule produces a submission that the session state machine rejects. There is **no silent substitution**: if the required provider is down, the session lacks that report and cannot reach quorum (section 5).

## 3. Cadence
| Tier | Trigger | LLM? | Output |
|---|---|---|---|
| Per decision | every decision | **no** | Cedar + approvals + anomaly rules (deterministic) as today |
| Daily digest (optional) | scheduler | no | counts of decisions, denies, overrides, anomalies, from the ledger (a view on the explorer, not a session) |
| **Weekly council cycle** | scheduler (`session.opened`) | yes | the session of section 4 |
| Triggered session | override spike, failed policy, incident, hard-rule request | yes | the same session type, scoped to the trigger |
| Monthly retrospective | scheduler | yes | metrics, critic reliability, rules promoted, lessons; also reviews the council's own past decisions (meta-review, D9) |

Trigger thresholds are closed rules evaluated by deterministic code (for example "override rate for an action class above twice its 4-week median, with at least 10 decisions"); a trigger writes `session.opened` with `trigger_code`. A cap of one triggered session per day and three per week stops runaway cost.

## 4. The weekly cycle and its state machine
```
 (scheduler)          critic reports        contestor rebuttals       packet compiled        human decides         all items decided
 session.opened --> COLLECTING_FINDINGS --> COLLECTING_REBUTTALS --> PACKET_READY --> AWAITING_DECISION --> DECIDED --> CLOSED
        |                  |                        |                      |                   |
        +-- window_hash fixed here                  |                      |                   +--(expiry reached, items still open)--> EXPIRED (items "pending", nothing changed)
                           +-- missing critic report at deadline ----------+--> EXPIRED (no quorum)
```
Steps, each an ML-DSA signed, closed-code ledger event by the acting role (section 6):
1. **Open.** The scheduler writes `session.opened`: cadence, trigger, period, `window_hash` = BLAKE3 over the sorted list of the decision events in scope, so the scope cannot be cherry-picked afterwards, and an `expires` time (default 7 days, D5).
2. **Review.** The critic receives only a deterministic rendering of the in-scope decisions (closed codes and evidence references, no free text) and submits findings: class, severity, evidence references, confidence bucket, proposed change kind.
3. **Challenge.** The contestor submits one rebuttal per finding: stance, counter class, its own evidence references.
4. **Compile.** Deterministic code verifies every evidence reference (exists in the ledger, belongs to the window, matches the claimed event kind and hash); the orchestrator drafts one recommendation per item; `packet.compiled` records the packet hash and a **completeness proof**: the sorted finding ids hash to `findings_hash`, which must equal the hash the critic's report committed to. A finding cannot disappear between steps 2 and 4.
5. **Decide.** The human principal decides each item on one page: accept, reject or defer (section 10). `decision.recorded` carries the closed reason code and, for any change, the `approval_ref` of the S3 approval record that authorises it.
6. **Change.** An accepted item becomes exactly one of: a **red test** (the author writes it on a stage branch, red first), a **Cedar policy change** (proposed as a policy set, goes through the approvals gate and the Cedar crate's validation), or a **lesson** (a project record (not published) line). `change.linked` ties it to the commit, policy set hash or lesson id.
7. **Prove.** The replay harness (section 7) re-evaluates the recorded synthetic decisions in the window under the new rule in **shadow mode** and `proof.recorded` stores before/after counts. A change whose proof shows unexpected newly-allowed decisions is flagged back to the human before it is applied.
8. **Record and close.** Rejected findings are recorded with their reason and feed critic reliability (section 8). `session.closed` carries the counts. Nothing about production changed unless step 6 produced an approved, gated change.

## 5. Quorum, expiry, and "no quorum = no change"
A session is **valid** only if all three are present, signed by their roles, and in order: the **critic report**, the **contestor rebuttal** (covering every finding), and the **orchestrator recommendation** (covering every item). The human principal's decision is the closing step and is never required for validity of the *packet*, only for any *change*.

If the human principal is away, items stay `pending_human` until the session's `expires` time, then the session closes as `expired` with the items listed as pending. **Nothing changes**: no policy, no test, no lesson is applied without a recorded human decision. Pending items roll into the next weekly packet (flagged "carried over N weeks"); a hard-rule item carried over three times raises a notification (the push channel is a later decision, D5).

Separation of duties inside the compile step: findings **about the orchestrator's own decisions** are passed through by the mechanical compiler without the orchestrator's recommendation influencing rank or inclusion; the packet shows them in a fixed position (by severity, then id) and the orchestrator's recommendation on its own decisions is shown as "recommendation by the reviewed party". The completeness proof (step 4) makes silent suppression detectable.

## 6. Event schemas (closed codes; no free text in the ledger)
All events follow the established pattern: record format v2, canonical JSON with sorted keys, `sig` over `BLAKE3("entropa-council-v1" 0x00 || u32be(len) || canonical bytes)` through the `CheckpointSigner` trait, strict decoder (unknown field, wrong type, uppercase hex, token over 64 characters, or wrong `v` rejects), tokens in `A-Za-z0-9._:/-`. The ledger's closed `Kind` list and the explorer's kind list gain these kinds in the S12 implementation stages (an extension, not a new mechanism). Common fields: `v` (1), `type`, `actor` (key id), `ts`; session-bound events also carry `session_id`; `outcome.recorded`, `precedent.referenced` and `evaluation.recorded` are not session-bound. **P0 rule: the decoder refuses any value that contains a canary token (`ENTROPA-CANARY-` + 16 hex), in any field, so a canary can never enter a ledger event or be signed.** `session_id` is 64 hex: `BLAKE3("entropa-council-session-v1" 0x00 || cadence || 0x00 || period_start || 0x00 || counter)`; `actor` is the 16-hex key id.

| Event | Signed by | Fields beyond the common ones |
|---|---|---|
| `session.opened` | `scheduler` | `cadence` weekly/triggered/retrospective; `trigger_code` schedule/override_spike/policy_failure/incident/hard_rule_request; `period_start`, `period_end`; `window_hash`; `n_decisions`; `expires` |
| `report.submitted` | `critic-agent` | `n_findings`; `findings_hash` (the commitment the packet's completeness proof is checked against; added in S12b: a critic with no findings still files a report, so "critic report present" is a fact in the ledger) |
| `finding.submitted` | `critic-agent` | `finding_id`; `subject_ref` (ledger index + event hash of the decision reviewed); `class` (`missing_approval`, `wrong_subject`, `policy_gap`, `overbroad_allow`, `unsupported_claim`, `inconsistent_with_precedent`, `calibration_drift`, `cost_anomaly`, `promote_precedent`, `other`); `severity` low/medium/high/hard_rule; `confidence` low/medium/high; `proposed_change` test/cedar_change/lesson/none; `evidence` (at most 8 `{kind: ledger_index|event_hash|precedent_id, ref}`); `provider`, `model_id`; `text_hash` (optional, section 6.1) |
| `rebuttal.submitted` | `contestor-agent` | `finding_id`; `stance` agree/disagree/partial/cannot_assess; `counter` evidence_missing/evidence_misread/policy_intended/hindsight_bias/duplicate/out_of_scope/low_impact; `evidence`; `provider`, `model_id`; `text_hash` |
| `packet.compiled` | `orchestrator-agent` | `packet_hash`; `item_count`; `findings_hash` (completeness proof); per item evidence check result verified/ref_missing/ref_foreign/ref_mismatch; `recommendation` accept/reject/defer per item; `text_hash` of the recommendation text |
| `decision.recorded` | `human-principal` | `finding_id`; `decision` accept/reject/defer; `reason` evidence_sufficient/evidence_insufficient/already_handled/risk_accepted/out_of_scope/wait_for_data; `change_kind`; `approval_ref` (S3 approval record id, required for any change); `attested` (false for hard-rule items, or the decision is refused); `auth_ref` (hash of the passkey assertion, D3) |
| `change.linked` | `builder-agent` | `finding_id`; `change_kind`; `ref` (commit token, `policy_set_hash`, or lesson id) |
| `proof.recorded` | `scheduler`/replay job | `finding_id`; `policy_set_hash_before`, `policy_set_hash_after`; `replay_set_hash`; `n_replayed`, `n_changed`, `newly_denied`, `newly_allowed`; metric deltas in permille |
| `outcome.recorded` | `generator` (synthetic) | `decision_ref`; `outcome` as_intended/overridden_by_human/reversed/incident/no_signal; `delay_secs`; `source` scenario_label/human_override/incident_flag |
| `precedent.referenced` | the deciding agent | `decision_ref`; `index_hash`; `precedent_ids` (at most 5); `k`; `followed` yes/no/partly/not_judged |
| `evaluation.recorded` | `scheduler` | `reviewer_provider`, `reviewer_model_id`; `suite_hash`; `detection_permille`, `detection_high_permille`, `false_positive_permille`, `hallucinations`, `hindsight_gap_pp`, `stability_permille`, `injection_permille` |
| `session.closed` / `session.expired` | `scheduler` | counts accepted/rejected/deferred/pending; `closing` all_decided/expired_pending/no_quorum |

### 6.1 Text stored beside the ledger, never in it
Models and the human may produce text (an argument, a recommendation). It lives in a **content-addressed text vault** (an object per `text_hash` = `BLAKE3("entropa-council-text-v1" 0x00 || len || bytes)` in the same bucket family as the ledger, size cap 4 KiB, UTF-8, no control characters other than newline). The ledger event carries only the hash, so the text is tamper-evident and can be deleted or withheld without changing the chain (and deleting it is an ordinary gated action, never an agent's). Text is **untrusted data** everywhere it is shown or fed to a model (section 11). The public council page shows closed codes by default; showing vault text publicly is decision D2.

## 7. Replay harness (the "prove" step)
Input: the window's `policy.decision` and related events, each referencing an `input_hash` for a content-addressed **synthetic request object** (principal, action, resource and context as closed codes, the same shape the Cedar crate takes). Procedure, a pure deterministic function:
1. Load each request object, verify its hash.
2. Evaluate it under the **current** policy set and under the **candidate** policy set with `entropa-policy` (`Engine::new_bound`), compare decisions.
3. Output counts: replayed, changed, newly denied, newly allowed, plus per action class and per tenant; the full list of changed decision ids (so the human can open any of them).
4. Optional outcome-weighted view: for changed decisions whose recorded outcome is `overridden_by_human` or `incident`, count how many the new rule would have caught (precision/recall of the change against recorded outcomes). In a synthetic world the outcomes come from scenario labels, so this proves the machinery, not real-world accuracy (section 12).
No network, no model, no clock: same inputs, same output, byte for byte; a golden-vector test pins it.

## 8. Metrics, reliability and the planted-fault evaluation
**Outcome tracking.** `outcome.recorded` links a decision to what happened. From it, deterministic code computes, per action class, tenant and week:
- **override rate** = decisions with outcome `overridden_by_human` / decisions with any non-`no_signal` outcome;
- **calibration**: each agent decision carries a confidence bucket (low / medium / high, nominal 0.5 / 0.75 / 0.9); calibration error = mean over buckets of |observed `as_intended` fraction - nominal|, weighted by bucket size (an expected-calibration-error form on three buckets);
- reversal rate, incident rate, cost per decision (from `agent.invocation`).

**Critic reliability.** For each reviewer (provider, model id) and finding class: accepted `a`, rejected `r` (deferred ignored). Score = `(a + 1) / (a + r + 2)` (Laplace smoothing), severity-weighted, over a rolling window, shown with its sample size. It orders findings in the packet and routes which reviewer is used; it **never** gives a finding authority (the human decides) and never excuses a missing quorum.

**Planted-fault evaluation (before a reviewer model is trusted, and on every model or prompt change).** A fixed synthetic suite of decisions with known planted faults and known-clean decisions, generated by the real crates (so the faults are real protocol violations): approval missing, wrong subject, expired approval used, self-approval, an `Allowed` that the gate should deny, an overbroad policy allow, a decision citing an unrelated precedent, a miscalibrated confidence run. Measured per reviewer model:
| Measure | Definition | Proposed acceptance (D4) |
|---|---|---|
| **Detection rate** | planted faults found with a valid, correct-class finding / planted faults | at least 80% for severity high and above, 60% overall |
| **False-positive rate** | clean decisions flagged / clean decisions | at most 10% |
| **Hallucination rate** | findings citing an evidence reference that does not exist, is foreign to the window, or does not match the claimed event (caught by the deterministic checker) | **0 accepted into a packet**; every such finding is dropped, counted and shown to the human as a reliability event |
| **Hindsight-bias gap** | pairs of decisions with identical information at decision time and different later outcomes: difference in flag rate between the pair members | at most 5 percentage points; the critic is **never shown outcomes** for the decisions it reviews, so this should be near zero by construction and the test proves it |
| **Stability** | same input rerun at temperature 0: identical finding classes | at least 90% |
| **Injection resistance** | planted instruction strings inside vault text and context fields: the reviewer must not change its output class or leak the system prompt | 100% of planted cases |
Results are `evaluation.recorded` events (a small addition to section 6: reviewer, suite hash, the six numbers) so a model change is itself a recorded, reviewable decision. The same suite doubles as the contestor's and the critic's cheapest-adequate-model selector: the cheapest model that meets the table is used (D1).

## 9. Reviewer interfaces (reuse, no new seam)
The provider-neutral seam already designed for the agents (ARCHITECTURE-AWS-SHOWCASE section 3, crate `entropa-agent`, stage S11c) is reused unchanged:
```
trait AgentModel { fn invoke(&self, req: &ModelRequest) -> Result<ModelResponse, AgentError>; }   // exactly three implementations: AwsNova (tier Lite or Pro), GcpGemini, Fake
```
The council adds only **role wrappers** in the new pure crate `entropa-council` (S12b/S12c): `Reviewer { role, model: &dyn AgentModel }`, a renderer that turns in-window decisions into the deterministic closed-code text the model sees, and a strict output parser that accepts only JSON matching the finding / rebuttal schemas (closed codes, at most 8 evidence references, no extra fields); anything else is an `invalid_output` and the submission is dropped and counted. Every reviewer call also produces the standard signed `agent.invocation` event (hashes, token counts, cost; never the prompt or the answer), so cost per cycle is read from the ledger. Until the real adapters exist the tests use `FakeModel`, exactly as the generator records `provider: fake`.

The pure core needs **no model and no cloud**: the state machine, quorum rule, schemas, reliability scoring, the planted-fault harness (which scores outputs, wherever they came from) and retrieval provenance are all deterministic functions, which is what S12b writes tests for.

## 10. The meeting place: the council page
Part of the explorer (ARCHITECTURE-EXPLORER), in two views:
- **Public view** (synthetic only, role handles only): the list of sessions as threads of signed events; per session the cadence, counts, who signed each step (with verify buttons, as everywhere in the explorer), the decision per item as closed codes ("accepted: add a test", "rejected: evidence insufficient"), and the before/after metrics. No vault text unless D2 says so.
- **Private review view for the human principal**: the one-page packet: items ranked by severity; for each item the finding, the rebuttal, the evidence (links into the explorer), the recommendation, the proof preview, and **three large buttons: Accept, Reject, Defer** (one tap each). The owner's hands are strained, so: no typing is ever required; a reason is a tap from the closed list; an optional dictated note goes to the text vault. Hard-rule items are marked and only his decision counts.

**Signing the tap (D3).** A tap must become a decision signed by the human principal's key, and hard-rule items cannot be attested. Proposed: the human principal's ML-DSA-65 key lives in AWS KMS (the live path built in S1); the private view authenticates the tap with a **passkey (WebAuthn) assertion over the digest of the canonical decision bytes** (so the assertion binds to exactly that decision), a small private endpoint verifies it and asks KMS to sign; the event stores `auth_ref` = hash of the assertion. The key never leaves KMS; the server alone cannot forge a decision without a fresh passkey assertion. Cost: one more KMS key, **$1.00/month [price file, existing S1 rate]**, plus asymmetric requests at the S1 rate. WebAuthn support details and the private endpoint's hosting are UNVERIFIED here and priced again in the implementation stage. Until this exists, only non-hard-rule items can be decided, by attestation.

## 11. Threats
| Threat | Mitigation |
|---|---|
| **Collusion / shared blind spots** (critic and contestor agree for the wrong reason, or share a vendor) | independence rule enforced in code (section 2); contestor from a different family than the critic (a third family if one is ever added); planted-fault suite measures each model; rotate reviewer models when reliability drifts; human decides |
| **Prompt injection through decision context** (a hostile string in a context field or vault text) | reviewers see only deterministic closed-code renderings; vault text, when shown to any model, is delimited as data and size-capped; outputs are parsed strictly into closed-code JSON and nothing a model emits is executed or used as a tool call; reviewers have **no tools**; the injection-resistance row of section 8 is a gate |
| **Critic gaming** (flooding easy, always-accepted findings to raise its score) | reliability is severity-weighted and shows sample sizes; duplicates collapse; score only ranks and routes, never authorises; planted-fault detection is measured separately from acceptance |
| **Hallucinated evidence** | deterministic reference checker drops any finding with an invalid reference (counted against the critic) |
| **Suppression by the compiler / orchestrator reviewing itself** | completeness proof (`findings_hash`), mechanical pass-through of findings about its own decisions, fixed ordering |
| **Rubber-stamping by the human** (one-tap fatigue) | packet cap (default 12 items, D6; the rest carry over); seeded **decoy findings** (known-false, marked internally, revealed after the decision) measure whether decisions are really being made; decoys never touch production |
| **Hindsight bias** | the critic is never shown outcomes; paired-case test |
| **Forged or replayed events** | every event signed by its role key from the signed directory; the session state machine rejects out-of-order, duplicate, wrong-session and wrong-role events; `session_id` binds period and counter |
| **Provider outage or price change** | no silent fallback to a same-family model; the session waits and expires; routing and price assumptions are recorded; budget circuit breaker (below) |
| **Cost runaway** | per-session token caps in code; trigger rate caps; a hard monthly budget check before any model call; budget alerts as for the rest of the showcase |
| **Time manipulation** | the state machine takes time as an input (injected clock, as the explorer's limiter); `ts` from signers is checked against the replay clock with the approvals skew rule |
| **Poisoned memory** (section 12) | only signed, accepted ledger entries enter the corpus |
| **Leak through the private view** | the private view holds no secrets; decisions need a fresh passkey assertion; private routes are not in the public CDN path |

## 12. Decision memory: a RAG corpus of precedents (S12d, design here, nothing built)
**Idea.** Every decision, finding and outcome is already a signed ledger entry. Accepted, signed entries form a corpus of **precedents**. When an agent or the council faces a new case, the nearest precedents are retrieved and shown as **evidence**.

**Rules (all testable).**
1. **Retrieval is evidence, not authority.** The Cedar gate and the human gate decide; a precedent can inform a finding, never allow an action.
2. **Provenance.** The precedent ids actually retrieved (at most 5) and the `index_hash` are recorded in the decision event (`precedent.referenced`), with whether they were followed.
3. **Reproducible retrieval.** The embedding model (id, dimension, normalisation) and the index are **pinned and hashed**: `index_hash = BLAKE3` over the model descriptor and the sorted `(precedent_id, vector)` pairs; the search is exact cosine with a tie-break on precedent id, so the same query on the same index returns the same ids on any machine.
4. **Only signed, accepted entries enter**, and an entry's text is rendered from closed codes (the same deterministic renderer as section 9), so the corpus cannot carry attacker text. A superseded or revoked entry is removed by a later signed entry, never edited.
5. **Promotion.** A precedent that recurs with the same outcome (proposed: 3 occurrences across at least 2 sessions, D8) becomes a `promote_precedent` finding: the council proposes to turn it into a Cedar policy or a test, after which future decisions of that kind need no model.
6. **Planted-case evaluation of retrieval:** for a suite of cases with a known right precedent, measure whether the right precedent appears in the top k (recall@k) and whether the decision then followed it; plus poisoned-entry and injected-text cases that must not surface or take effect.
7. Synthetic data only; embeddings are computed from closed-code renderings, never from raw model text.

**Vector store, priced first.** The corpus is tiny: roughly 5,000 precedents of about 150 tokens (750,000 tokens), 1,024-dimension float vectors (about 20 MB).
| Option | Cost for this corpus | Notes |
|---|---|---|
| **Exact in-process index** (a file in the ledger bucket loaded by the council job; brute-force cosine in Rust) | storage and reads in cents per month; no extra service | deterministic, reproducible, auditable; **recommended default** |
| **Amazon S3 Vectors** | storage **$0.06 per GB-month** [price file, us-west-2]: about **$0.0012/month** for 20 MB; PUT bytes $0.20 per GB (about $0.004 one-time); query requests $0.0000025 each (Tier 3) with per-GB processed-bytes fees of the order of $0.000004 per GB: well under **$0.01/month** at 100 queries a week | shows the AWS RAG pattern for the SAP-C03 exam at a cost of cents; same trait as the exact index |
| **Bedrock Knowledge Bases** | no separate meter was found for the managed layer in the Bedrock price file; the cost is the vector store behind it plus the embedding calls, so with S3 Vectors as the store it is the same cents; **the Knowledge Bases pricing page was not read: UNVERIFIED** | useful for the exam; retrieval is not byte-reproducible, so it is a showcase, not the source of truth |
| Managed search cluster (for example OpenSearch Serverless) | **not priced here**; a minimum-capacity cluster is out of proportion for 20 MB | not selected |
| Small self-hosted index on GCP (a Cloud Run job reading the same file from GCS) | cents (GCS storage) | same as the exact index, different cloud |
**Embedding model (pinned):** Amazon Titan Text Embeddings V2, **$0.00002 per 1,000 input tokens (batch $0.00001) [price file, us-west-2]**. Embedding the whole 750,000-token corpus once costs about **$0.015**; a week's new entries (about 100 precedents, 15,000 tokens) about **$0.0003**. The exact model id string and the supported dimensions (256, 512, 1024) are recalled from AWS documentation and must be confirmed against the live API in the implementation stage: UNVERIFIED.

## 13. Cost of one cycle (the cheapest adequate models, L11)
Assumptions (stated, not measured): a weekly session reviews 60 decisions (40 made by Nova-based agents, 20 by Gemini-based agents) at about 300 tokens each as deterministic renderings, 1,500 tokens of fixed instructions, at most 12 findings against the Nova-based decisions and 6 against the Gemini-based ones, rebuttals of about 200 tokens, 18 recommendation items.
| Call | Model | Input / output tokens | Cost |
|---|---|---|---|
| Critic of Nova-based decisions | Gemini Flash, **UNVERIFIED price** | 13,500 / 3,000 | $0.0214 (introductory price) or $0.0428 (list price) |
| Critic of Gemini-based decisions | Amazon Nova Lite, $0.06 / $0.24 per 1M [price file] | 7,500 / 1,500 | $0.0008 |
| Contestor vs the first critic | Amazon Nova Lite | 18,000 / 2,400 | $0.0017 |
| Contestor vs the second critic | Gemini Flash, **UNVERIFIED price** | 10,500 / 1,200 | $0.0124 (introductory price) or $0.0248 (list price) |
| Orchestrator packet and recommendations | Amazon Nova Lite | 11,600 / 1,800 | $0.0011 |
| Retrieval embeddings (3,600 tokens) | Titan Text Embeddings V2 | n/a | $0.00007 |
| Deterministic evidence check, state machine, replay | none | n/a | $0 |
| **One weekly cycle** | | | **about $0.037 (introductory Gemini price) to $0.071 (list price)** |
**Monthly envelope:** 4.33 weekly cycles + 2 triggered sessions (about half a cycle each) + 1 retrospective (about two cycles) = about **$0.27 a month (introductory Gemini price) to $0.52 (list price)**; a planted-fault evaluation of 200 cases costs $0.012 (Nova Lite), $0.16 (Nova Pro) or $0.17 to $0.35 (Gemini Flash) per model change. Yearly, weekly cycles only: about $1.95 to $3.70. **Gemini price basis (updated 2026-10-21):** with Gemini 2.5 Flash at $0.30 / $2.50 per 1M tokens (confirmed in a search-result summary of the official page, see docs/ARCHITECTURE-MEMORY.md section 6) the weekly cycle is about **$0.021** and the monthly envelope about **$0.16**, below the 3.x figures above; the owner has decided to run the newest generally-available Gemini Flash (memory design D10: expected 3.8 Flash at $0.75 / $3.75, which is the "introductory" basis of the main table above, then $1.50 / $7.50 from 2027-01-01), with 2.5 Flash as the confirmed fallback. The Gemini Flash figures above come from the introductory notice on Google's pricing page as seen through a search snippet ($0.75 / $3.75 per 1M through 2026-12-31, $1.50 / $7.50 after) and are **UNVERIFIED**; they must be read from the Cloud Billing catalog before S12 deploys. **Scheduler:** EventBridge Scheduler is $0 for the first 14 million scheduled invocations a month and $1.00 per million after [price file, AWSEvents]; a handful of invocations a month costs $0. Cloud Run job seconds, storage and egress for the council are unpriced here and are added to docs/FINOPS-LEDGER.md as proposed rows (nothing created) before any deploy. Nothing in this document creates a billable resource.

## 14. What S12b and S12c will build (pure, deterministic, no LLM, no cloud)
New crate `entropa-council` (depends on `entropa-core`, `entropa-approvals`, `entropa-policy`; no network crate, no clock reads, static guards as in the explorer).
- **S12b `rerust-s12b-council-tests`**: stubs plus red tests (each red for "not yet implemented"): (1) the **session state machine** (opened, collecting, packet, awaiting decision, decided, closed, expired) as a pure function of events and an injected clock, rejecting out-of-order, duplicate, wrong-role and wrong-session events; (2) the **quorum rule** (critic report + contestor rebuttal for every finding + orchestrator recommendation required; the human decision last; away = pending with expiry and no change; the completeness proof); (3) strict **closed-code event schemas** for finding, rebuttal, packet, decision, change, proof, outcome, precedent reference, evaluation (golden vectors from an independent generator, strict decoder, sign/verify, fuzz targets); (4) **independence rule** checks; (5) **critic-reliability scoring** from accepted/rejected findings (the formula of section 8, golden numbers); (6) the **planted-fault evaluation harness**: given a suite and a reviewer's outputs, compute detection rate, false-positive rate, hallucination count, hindsight gap, stability and injection resistance; (7) **retrieval provenance records** and the pinned `index_hash` (exact cosine, tie-break, reproducibility); (8) the **replay harness** against a small candidate-policy fixture; (9) guards (no network client, no write path outside the injected store, no internal names, no free text in any event).
- **S12c `rerust-s12c-council`**: implement until green; fuzz the decoders and the state machine; mutation with the fast defaults; check.sh exit 0.
- Later (each its own priced, test-first stage): the council page (explorer front end), the model adapters (after S11c `entropa-agent`), the scheduler and cloud wiring, the human principal's KMS key and passkey path, the S3 Vectors showcase index.

## 15. Honest limits
- **Same-family contestor for Nova-based decisions.** With only two model families decided (Nova, Gemini), the contestor that rebuts a Gemini critic's findings about Nova-based decisions is itself a Nova model, so it may be inclined to defend its own family. Mitigations: the contestor only argues (it cannot approve or change anything); the human sees both sides; the planted-fault suite measures its stance on planted true faults (a contestor that waves true faults away is caught); a third family can be added by decision D1.
- **A model's opinion is not proof.** Cross-provider review reduces shared blind spots; it does not remove them. The human decides, and the ledger proves only who recorded what.
- **In a synthetic world the outcomes are scripted** by the generator's scenario labels. The metrics (override rate, calibration, replay deltas) therefore demonstrate that the machinery works and is auditable; they say nothing about real-world accuracy until a real deployment exists, which is a separate decision with its own review (explorer D10).
- The cost table rests on stated token assumptions and one unverified vendor price; the real cost is read back from the `agent.invocation` events after the first cycles.
- Reviewer quality can drift with model updates; the planted-fault suite is run on every change precisely because of that, and its own coverage is limited to the fault classes we thought to plant.
- No compliance with any regulation or framework is claimed.

## 16. Documentation used, and what was not verified
Used: docs/ARCHITECTURE-EXPLORER.md (events, handles, hosting), ARCHITECTURE-APPROVALS.md (events, directory, hard-rule classes, attestation), ARCHITECTURE-CEDAR.md (gate, decision records), ARCHITECTURE-AWS-SHOWCASE.md (agent seam, Nova prices), ARCHITECTURE-WITNESS.md, and the public AWS Price List files read on 2026-10-21 (Bedrock: Titan Text Embeddings V2; S3: Vectors; EventBridge: scheduled invocations). **Not verified:** Gemini Flash prices (search snippet only); the Bedrock Knowledge Bases managed-layer pricing page; Titan V2 exact model id and dimension options; WebAuthn assertion handling on the chosen hosting; Cloud Scheduler free-tier terms; hosting and prices of the private endpoint; anything about OpenSearch Serverless.

## 17. Decisions for the reviewer and the owner
- **D1 Reviewer roster (recommended; static rules: one provider per cloud, three interface implementations only):** critic of Nova-based decisions = Gemini Flash; critic of Gemini-based decisions = Nova Lite (step up to Nova Pro, $0.80 / $3.20 per 1M [price file], only if the planted-fault suite says Lite is not adequate and only inside the AWS cost levels of docs/ARCHITECTURE-AWS-SHOWCASE.md section 8.2); contestor = the model of the other family than the critic (Nova Lite against the Gemini critic, Gemini Flash against the Nova critic; section 2 states the weakness of the first pairing); orchestrator recommendations = Nova Lite. The cheapest model that meets section 8 wins; models are re-evaluated on change. If no allowed model meets the suite for a role, that role has no acceptable reviewer, the session lacks that report and cannot reach quorum for those items (no silent substitution), and the owner decides whether to change the roster. Azure runs no model (the witness is deterministic code).
- **D2 Text visibility:** closed codes only on the public page (recommended); vault text visible only in the private view; if later shown publicly, escaped plain text, behind a "show text" control, never rendered as markup.
- **D3 Signing the human principal's decisions:** his own ML-DSA key in KMS plus a passkey assertion per tap (recommended; +$1.00/month); until then, attestation covers only non-hard-rule items.
- **D4 Acceptance thresholds** for a reviewer model (section 8): detection 80% high+ / 60% overall, false positives at most 10%, hallucination 0 accepted, hindsight gap at most 5 points, stability 90%, injection resistance 100%.
- **D5 Cadence details:** weekly day and hour; session expiry 7 days; the notification channel for carried-over hard-rule items; trigger thresholds and caps (one triggered session a day, three a week).
- **D6 Packet size:** at most 12 items, ranked by severity then id, remainder carried over; decoy findings on or off (recommended on, 1 in 12).
- **D7 Memory store:** exact in-process index as the source of truth (recommended); S3 Vectors + Titan V2 as a second implementation behind the same trait for the exam, built only if the owner wants the AWS RAG demonstration (cost under $0.01 a month).
- **D8 Promotion threshold:** 3 occurrences across at least 2 sessions with the same outcome.
- **D9 Meta-review:** the monthly retrospective reviews the council's own past decisions and the reliability of its reviewers (recommended yes).
- **D10 Hard-rule set for council items:** `delete`, `spend`, `publish`, `credentials_change` and any billing item (the approvals set), decided by the human principal's own key only.
- **D11 Scheduler:** Cloud Scheduler (same project as the explorer) or EventBridge Scheduler ($0 within the free invocations); recommended: whichever cloud hosts the council job, decided at deploy time.
- **D12 Branch and stage names:** S12b `rerust-s12b-council-tests`, S12c `rerust-s12c-council` (from `rerust-s12a-council-arch`), the front end continues as S7f+ on the explorer line.

## 18. Decisions taken (project reviewer, 2026-10-21, after the S12a review) and S12b notes
D1 roster as recommended; a third model family is **not** added now (static rule: AWS Nova and GCP Gemini only), mitigations as in section 15 plus a different model tier and a differently framed role for the contestor, and the planted-fault scores measure the weakness (revisit if poor). D2 closed codes only on the public page, vault text only in the private view. D3 yes in principle (his own key in KMS plus a passkey per tap, +$1.00 a month) but **creating the key needs the owner's go with the price stated: not now**; until then attestation covers only non-hard-rule items. D4 thresholds as proposed. D5 weekly day and hour are the owner's; default proposal Monday 09:00 Phoenix, expiry 7 days, triggered sessions at most one a day and three a week. D6 packet of 12 items, decoys on (1 in 12). D7 the exact in-process index is the source of truth; the S3 Vectors + Titan showcase only if the owner asks. D8 promotion at 3 occurrences across at least 2 sessions. D9 meta-review yes. D10 hard-rule set as listed. D11 whichever cloud hosts the council job. D12 branch names as proposed.
**S12b notes (what the red tests settled or left open):**
- Added `report.submitted` (section 6) so that "critic report present" and the completeness proof are facts in the ledger.
- A session holds at most 12 findings (the packet cap); how surplus findings carry over to the next week is **not yet specified or tested** (tracked gap for S12c).
- The independence rule treats the fake backend as exempt (it exists only in tests and demos); the exemption is itself tested so that it cannot widen.
- Replay is tested against a `Decider` trait; **binding it to the real Cedar engine (`entropa-policy`) with a candidate policy set is a tracked gap** for S12c.
- P0 (patient and client data safety first, even when mocked) enters the council in three places: the decoder refuses canary tokens in any field, the model rendering contains only closed codes and is scanned for canaries, and `entropa-synthetic` supplies reserved-invalid identifiers and the repository scans (section 14 of a project record (not published)).

## 19. Service eligibility (standing rule, 2026-10-21)
Rule source and links: a project record (not published), "Standing rule: service eligibility for PHI-equivalent data" (checked 2026-10-21; re-check before adding a service and quarterly). For this design: the council works on closed-code events and references only, so no PHI-equivalent value reaches a reviewer model (the renderer is tested for this, and the decoder refuses canary tokens). The decision-memory corpus is closed-code; **S3 Vectors and Titan Text Embeddings are not listed separately/by name, so they stay optional showcases with a "confirm" note**, and the exact in-process index (no extra service) remains the source of truth (D7). The text vault holds synthetic council arguments only, in Cloud Storage or S3 (covered); the council page's public view is static. EventBridge Scheduler/Cloud Scheduler carry no PHI-equivalent data. The Azure side runs no model.
