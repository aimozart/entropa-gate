#!/usr/bin/env bash
# Deploys a validator to Cloud Run via `gcloud run deploy --source=.` (uploads the
# local working directory straight to Cloud Build — see the project notes for why
# this is used instead of a webhook-triggered build). Extracted into a real,
# testable script so the deploy invocation itself has coverage, not just the
# manual command copied around in docs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/gcloud-runner.sh"

require_env PROJECT_ID
require_env REGION
require_env SERVICE

SOURCE_DIR="${SOURCE_DIR:-.}"

existing_services="$("${GCLOUD_BIN:-gcloud}" run services list \
    --region="$REGION" --project="$PROJECT_ID" --format=json)"
if ! grep -q "\"$SERVICE\"" <<<"$existing_services"; then
    echo "warning: $SERVICE is not yet a known service in this project — proceeding anyway, since a brand-new service is a real, valid case" >&2
fi

run_gcloud run deploy "$SERVICE" \
    --source="$SOURCE_DIR" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --quiet

if [ "${DRY_RUN:-0}" != "1" ]; then
    "${SMOKE_CMD:-$SCRIPT_DIR/smoke.sh}"
fi
