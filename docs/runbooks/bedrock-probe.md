# Runbook: the tiny Bedrock probe (S11b-prep)

Purpose: find out, for about **$0.000002 a call** (hard cap $0.00003), whether your AWS account, quota and the $198 credit allow Amazon Nova Lite on Amazon Bedrock
(docs/ARCHITECTURE-AWS-SHOWCASE.md section 9). **Status: the probe ran on 2026-10-21 with `amazon.nova-lite-v1:0`: two successful calls (HTTP 200, about $0.0000022 each); the open item is the Billing check at the end.** **You (the owner) run it; no agent runs AWS commands.** It creates no AWS resource, so there
is nothing to tear down. It reads credentials only from your terminal's environment, never from `~/.aws`, and prints metadata only
(model id, region, HTTP status, request id, token counts, an estimated cost), never a secret and never the model's answer.

## What it does
One `Converse` call to the model you name: a fixed synthetic prompt ("Reply with the single word: ok", well under 300 input tokens), `maxTokens` 50,
temperature 0. Estimated cost with the Price List numbers (Amazon Nova Lite, us-west-2, 2026-10-21): 20 input tokens x $0.06/1M + 3 output tokens x $0.24/1M
is about $0.0000019 for a typical answer; the hard cap (300 in, 50 out) is $0.00003. The estimate is model-aware for the Amazon Nova family in the plan (Lite $0.06 / $0.24, Pro $0.80 / $3.20 per 1M; Micro for reference); for any other model id the output says `est_cost_usd=unknown`.

## Steps
1. **Credentials.** Export short-lived credentials in the terminal you will run it from, your usual way. Needed variables: `AWS_ACCESS_KEY_ID`,
   `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (if your credentials have one). Do not put them in a file in the repo. Region defaults to `us-west-2` (`AWS_REGION` to change).
   Permission needed: `bedrock:InvokeModel` (the Converse API uses it) on the model or inference profile.
2. **Model access.** Amazon Nova is a first-party Amazon model: **no Anthropic use-case form and no AWS Marketplace agreement apply**, and the 2026-10-21 probe succeeded without either.
   This is a single account: do **not** use any AWS Organizations step (forbidden by the rules). If anything asks to upgrade the plan or add a payment method, stop.
   A new account can have a default quota of zero for a model: if the call is throttled or denied for quota, request an increase in Service Quotas (free).
3. **The model id (read-only, free).** The id that worked on 2026-10-21 is `amazon.nova-lite-v1:0`: `export BEDROCK_MODEL_ID='amazon.nova-lite-v1:0'`. To see the inference profiles that exist for Nova in the region:
   `aws bedrock list-inference-profiles --region us-west-2 --query "inferenceProfileSummaries[?contains(inferenceProfileId, 'nova')].[inferenceProfileId,inferenceProfileName]" --output text`
   A profile id such as `us.amazon.nova-lite-v1:0` is also recognised by the cost estimate.
4. **Offline check (no network, no credentials):** `scripts/probe-bedrock.sh --selftest` should end with `OK` (23 tests: the published SigV4 vectors, hand-written canonical requests for model ids with `:` and `/`, the 300/50 token caps, no secret in any output, safe error output, a data-minimal record).
5. **Run the probe:** `scripts/probe-bedrock.sh`. Expected output (values will differ):
   ```
   model_id=<id>
   region=us-west-2
   http_status=200
   request_id=<uuid>
   input_tokens=20
   output_tokens=3
   stop_reason=end_turn
   est_cost_usd=0.0000019
   ```
   It also writes the same facts (no secrets, no answer) to `docs/evidence/s11b-probe-result.json`. On an error it prints `http_status`, `request_id`,
   `error_type` (from the `x-amzn-ErrorType` response header; Bedrock does not put it in the body) and `error_message` (at most 120 characters, 12-digit
   account numbers masked as `<account>`, access key ids as `<key-id>`); it never prints any other header or any credential. What the error type means:
   - `InvalidSignatureException`: the request signature does not match. The signing is checked offline (23 tests: the AWS documentation IAM example, hand-written
     canonical requests for model ids containing `:` and `/`, an independent signature recomputation), so first suspect the credentials: a wrong or truncated secret,
     or a **temporary key** (access key id starting `ASIA`) used without its `AWS_SESSION_TOKEN`. A key starting `AKIA` is long-term and needs no token. The script strips
     spaces and newlines pasted around the values.
   - `UnrecognizedClientException` / `ExpiredTokenException`: the key or token is not valid for this region/partition, or the temporary token expired.
   - `AccessDeniedException`: a missing permission (`bedrock:InvokeModel` on the model or profile ARN), or the model is not enabled for the account.
   - `ValidationException`: wrong model id (step 3), or a model that needs an inference profile id instead of the plain model id.
   - `ThrottlingException` / quota text: step 2 quota note.
   If you are unsure, compare with the CLI using the very same environment: `aws bedrock-runtime converse --region "$AWS_REGION" --model-id "$BEDROCK_MODEL_ID" --messages '[{"role":"user","content":[{"text":"ok"}]}]' --inference-config '{"maxTokens":5}'`
   (the CLI picks up the same variables), and paste us the printed `error_type` and `error_message` lines.
6. **Tell the reviewer/the author the result** (paste the printed lines; they contain no secrets). We then record it in docs/FINOPS-LEDGER.md and commit the result file.

## Next day: check Billing (the real question: did the credit apply?)
In the AWS console, **Billing and Cost Management**:
- **Bills**: open the current month and look for the line. Is it under **Amazon Bedrock** (billed by AWS) or under **AWS Marketplace** (third-party model billed through Marketplace)? Note the exact service name.
- **Credits** page: does the balance drop by that amount, or is the charge shown as an unpaid charge? Also check the line's "credits applied" in **Cost Explorer** (group by Service, tick "Credits" in the charge-type filter).
- The amount is tiny (about $0.000002 a call); it may show as $0.00. If it rounds to zero, repeat the probe 20 times (still about $0.0001) or look at the usage quantity in Cost Explorer (usage type with `input_tokens` / `output_tokens`) and the credit column.
Record what you see (service name, credit applied yes/no) and send it to the reviewer.

## Decision rule (from the design)
Amazon Nova Lite is the decided AWS model and the probe already succeeded with it; the open question is only the credit.
- **Credit applied to the Nova line:** proceed with Nova Lite as designed (S11c onward).
- **Credit NOT applied (the charge is paid by card or shows as due):** nothing beyond the probe is deployed on AWS until the owner decides; the showcase then runs on Gemini on the GCP credit through the same provider-neutral interface (docs/ARCHITECTURE-AWS-SHOWCASE.md section 9). No other provider is tried.

## Safety notes
- Nothing here changes the account, billing, plan or budgets.
- If you ever see a charge larger than a cent from this probe, stop and tell us: the script has hard caps, so that would mean something else is calling Bedrock with your credentials.
