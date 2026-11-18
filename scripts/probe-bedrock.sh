#!/usr/bin/env bash
# One tiny Bedrock Converse call (S11b-prep). The owner runs it; see docs/runbooks/bedrock-probe.md.
#   scripts/probe-bedrock.sh --selftest     offline: SigV4 test vector and output checks, no network, no credentials
#   scripts/probe-bedrock.sh                the call (needs AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, optional AWS_SESSION_TOKEN,
#                                           BEDROCK_MODEL_ID in the environment; AWS_REGION defaults to us-west-2)
# Credentials are passed into the container by NAME only (never on a command line) and never read from ~/.aws.
set -euo pipefail
source "$(dirname "$0")/lib-docker.sh"
if [ "${1:-}" = "--selftest" ]; then
  in_dev python3 -I scripts/tests/test_probe_bedrock.py
else
  export PROBE_RECORD="${PROBE_RECORD:-/work/docs/evidence/s11b-probe-result.json}"
  IN_DEV_PASS_ENV="AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_REGION BEDROCK_MODEL_ID PROBE_RECORD" \
    in_dev python3 -I scripts/probe_bedrock.py
fi
