#!/usr/bin/env bash
# Smoke test of the deployed platinum ingest with the caller's own Google login (needs roles/run.invoker).
# Writes ONE synthetic decision to the cloud ledger, then verifies the whole ledger. Prints no token.
set -euo pipefail
U=${1:-https://entropa-platinum-loqc3sut7a-uc.a.run.app}
TOK=$(gcloud auth print-identity-token)
H=(-H "Authorization: Bearer $TOK")
echo "pubkey:";  curl -sf "${H[@]}" "$U/v1/pubkey" | cut -c1-64; echo
echo "log one synthetic decision:"
curl -sf -X POST "${H[@]}" -H "Content-Type: application/json" "$U/v1/decision" -d '{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"cloud smoke test question","output":"SELECT night FROM platinum_metrics_daily LIMIT 1","run_id":"run-cloud-smoke-1","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":1,"cost_micro_usd":1}'; echo
echo "verify:"; curl -sf "${H[@]}" "$U/v1/verify"; echo
echo "without credentials (expect 403):"; curl -s -o /dev/null -w "%{http_code}\n" "$U/v1/verify"
