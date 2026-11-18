# FinOps ledger (AWS, account <aws-account-id>, region us-west-2). Forecast first, then actual.
Rules: cost + teardown written before anything billable; tags project=entropa; nothing left running without an entry here; deletes need Scott's exact word + standalone yes/no.

| Created (Phoenix) | Resource | Forecast | Actual | Teardown |
|---|---|---|---|---|
| 2026-10-20 | KMS key 805943d1-18f9-4cee-b376-7046fb8dccec (alias/entropa-checkpoint-signer), ML_DSA_65, SIGN_VERIFY | $1.00/month key + $0.15 per 10,000 asymmetric requests (general asymmetric rate; ML-DSA-specific rate not shown in the price file); about 200 test signings = about $0.003 | (fill from billing after the first full day) | `aws kms schedule-key-deletion --region us-west-2 --key-id 805943d1-18f9-4cee-b376-7046fb8dccec --pending-window-in-days 7` (and delete alias entropa-checkpoint-signer) |

Evidence: crates/kms/tests/aws_kms_ml_dsa_65 vector: a signature from this real KMS key verifies under Entropa's own ML-DSA-65 verifier (verified 2026-10-20). KMS public key = 22-byte SPKI wrapper (308207b2300b0609608648016503040312038207a100) + 1952-byte raw key; signature = 3309 bytes.

| 2026-10-20 | S1 live test (no new resource): 1 GetPublicKey + 3 Sign on the existing key | cap 10 Sign + 1 GetPublicKey, about $0.0002 | 4 requests, about $0.00006 (reported by the reviewer; see a stage record (not published)) | nothing to tear down |

## Proposed, NOT created (Azure witness, S5a design 2026-10-21; nothing below exists; needs the owner's go and a restated price)
Prices: Azure Retail Prices API, westus2, fetched 2026-10-21 (docs/ARCHITECTURE-WITNESS.md section 6). Tag project=entropa. Teardown (the owner runs it): `az group delete --name rg-entropa-witness --yes --no-wait`.

| Planned | Resource | Forecast | Actual | Teardown |
|---|---|---|---|---|
| about 2026-11-05 | Resource group rg-entropa-witness | $0 | not created | az group delete (above) |
| about 2026-11-05 | Function app, Consumption (Linux, custom handler) | $0.00 compute inside the free tier (1,000,000 executions and 400,000 GB-s a month); about 1,000 requests a month | not created | with the group |
| about 2026-11-05 | Storage account Standard_LRS (host + state blob) | about $0.01 to $0.50 a month | not created | with the group |
| about 2026-11-05 | Key Vault Standard (witness key secret) | $0.03 per 10,000 operations, negligible | not created | with the group (soft-deleted 90 days) |
| before deploy | Budget alert $5 (free) | $0 | not created | with the group |

## Proposed, NOT created (AWS + GCP agentic showcase, S11a design 2026-10-21; nothing below exists; each stage needs the owner's go and a restated price)
Prices: AWS Price List bulk files, us-west-2, fetched 2026-10-21 (docs/ARCHITECTURE-AWS-SHOWCASE.md section 7); GCP Vertex prices not confirmed. Teardown (the owner runs it): `aws cloudformation delete-stack --stack-name entropa-showcase --region us-west-2`; `gcloud run services delete ...` per service. Tags project=entropa.

| Planned | Resource | Forecast | Actual | Teardown |
|---|---|---|---|---|
| S11b | one Bedrock Converse call, Amazon Nova Lite, at most 300 input + 50 output tokens | $0.00003 at the cap | DONE: 2 successful calls (HTTP 200), about $0.0000022 each (the owner ran them 2026-10-21); billing check pending | none (no resource created) |
| S11e-g | Lambda arm64, API Gateway HTTP API, DynamoDB on-demand, Step Functions, S3, CloudWatch (7-day logs, 10 alarms), AgentCore Runtime + Gateway (explainer) | base case about $14.4 a month in total, about $12.4 with the bank agent on Gemini (section 8); acceptable range up to about $25, Pro off over about $25, all AWS model calls paused at the $45 hard cap (section 8.2); idle about $2 to $3 a month | not created | delete-stack |
| S11e-g | Bedrock model usage (Nova Lite 90%, Nova Pro 10% of calls; Pro only for flagged hard cases) and Guardrails (clinic) | $2.43 + $3.60 + $3.60 a month, included above ($1.62 + $2.40 + $3.60 with the bank on Gemini) | not created | none (usage only) |
| S11h | Cloud Run service(s) in entropa-testnet for the Vertex Gemini backend, scale to zero | on the GCP credit; SKU prices to be read before the stage | not created | gcloud run services delete |
| S11i | budget alert thresholds $60 / $120 / $160 cumulative (alerts only) | $0 | not created | with the budget |

## S11b probe (prepared 2026-10-21, NOT run; the owner runs it)
| Planned | Resource | Forecast | Actual | Teardown |
|---|---|---|---|---|
| after the owner's go | one Bedrock Converse call on Amazon Nova Lite, fixed 300-token-max prompt, 50-token-max answer (scripts/probe-bedrock.sh) | $0.00003 hard cap, about $0.0000019 typical | ran: see the next row | none (no resource created) |
| 2026-10-21 (the owner ran it) | two Converse calls, amazon.nova-lite-v1:0, us-west-2 | about $0.0000022 per call (20 in / 3 out tokens at $0.06 / $0.24 per 1M) | 2 successful calls (HTTP 200); **billing check pending**: whether the credit applied and under which service line (Amazon Bedrock or AWS Marketplace) | none (no resource created) |

## Proposed, NOT created (public explorer on GCP, S7a design 2026-10-21; nothing below exists; each stage needs the owner's go and a restated price)
Prices: GCP list prices from training knowledge, UNVERIFIED (Google's price pages could not be read as text); read the exact SKUs from the console pricing calculator before S7g. Project entropa-testnet, labels project=entropa. Teardown (the owner runs it): see docs/ARCHITECTURE-EXPLORER.md section 11.

| Planned | Resource | Forecast | Actual | Teardown |
|---|---|---|---|---|
| S7g | Cloud Run service explorer-api (min 0, max 3) and Cloud Run job generator + 1 Cloud Scheduler job | inside the monthly free tier: about $0 | not created | gcloud run services/jobs delete, scheduler jobs delete |
| S7g | Cloud Storage bucket for the ledger | under $0.02 a month | not created | gcloud storage rm -r (after export) |
| S7g | Secret Manager, 6 secrets (log key, actor keys) | about $0.36 a month | not created | gcloud secrets delete |
| S7g | Firebase Hosting release (static front end + WASM), Artifact Registry image | $0 within free tiers | not created | firebase hosting:rollback / disable |
| S7g | budget alert $10 (alerts only) | $0 | not created | with the budget |

## Proposed, NOT created (Decision Review Council, S12a design 2026-10-21; nothing below exists; needs the owner's go and a restated price at each build stage)
| Item | Forecast | Teardown |
|---|---|---|
| Weekly council cycle (model calls through Bedrock Nova Lite and Vertex Gemini Flash) | about $0.037 a cycle (introductory Gemini price, UNVERIFIED) to $0.071 (list price); about $0.27 to $0.52 a month with triggered sessions and the monthly retrospective | nothing to tear down: calls stop when the scheduler job is disabled |
| Scheduler trigger (EventBridge Scheduler or Cloud Scheduler) | EventBridge: $0 for the first 14 million scheduled invocations a month (AWS Price List) | disable or remove the schedule (the owner's word for any delete) |
| Decision-memory embeddings (Titan Text Embeddings V2) | $0.00002 per 1K input tokens (AWS Price List); about $0.015 one-time for 750,000 tokens, about $0.0003 a week after | none |
| Decision-memory store: exact index file in the ledger bucket | cents a month | with the bucket |
| Optional S3 Vectors showcase index | storage $0.06 per GB-month (AWS Price List): about $0.0012 a month for 20 MB; requests under $0.01 a month | delete the vector index (the owner's word) |
| Second KMS key for the human principal's decisions (decision D3) | $1.00 per key-month plus asymmetric requests at the S1 rate | schedule key deletion (the owner's word; deletion has a waiting period) |
Details and assumptions: docs/ARCHITECTURE-COUNCIL.md sections 12 and 13. Tags project=entropa on every resource when created.

## Proposed, NOT created (decision memory, S12d-a design 2026-10-21; nothing below exists; needs the owner's go and a restated price at each build stage)
| Item | Forecast per month | Teardown |
|---|---|---|
| A. Exact lexical index file in a versioned bucket (each cloud) | under $0.001 (S3 Standard $0.023 per GB-month, AWS Price List) | with the bucket |
| B/C. Optional dense index: Titan Text Embeddings V2 ($0.00002 per 1K tokens) + S3 Vectors ($0.06 per GB-month, $0.0000025 per query) | about $0.05; corpus embedded once for $0.015 | delete the vector index (the owner's word) |
| K. GCP alternative: Firestore vector index + gemini-embedding-001 | about $0.16 (embedding unit UNVERIFIED) | delete the collection (the owner's word) |
| Not selected, for the record: Bedrock Managed Knowledge Bases (about $9.0), OpenSearch Serverless (from $175 for one OCU), Vertex AI Vector Search (about $68 for one node), Vertex AI Search ($4.00 per 1,000 queries) | see docs/ARCHITECTURE-MEMORY.md section 6 | none (not created) |

