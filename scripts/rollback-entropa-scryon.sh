#!/usr/bin/env bash
# Rolls Cloud Run traffic back to a specific prior revision via
# `gcloud run services update-traffic`. Fails closed: a missing, ambiguous, or
# post-rollback-unhealthy target stops the script rather than guessing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/gcloud-runner.sh"

require_env PROJECT_ID
require_env REGION
require_env SERVICE
require_env REVISION

if [[ "$REVISION" == *,* ]]; then
    echo "error: REVISION is ambiguous — pass exactly one revision, not a list ($REVISION)" >&2
    exit 1
fi

existing_revisions="$("${GCLOUD_BIN:-gcloud}" run revisions list \
    --service="$SERVICE" --region="$REGION" --project="$PROJECT_ID" --format=json)"
if ! grep -q "\"$REVISION\"" <<<"$existing_revisions"; then
    echo "error: revision $REVISION does not exist for service $SERVICE — refusing to roll back to it" >&2
    exit 1
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "Would roll back $SERVICE ($REGION, $PROJECT_ID) to revision: $REVISION"
else
    run_gcloud run services update-traffic "$SERVICE" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --to-revisions="$REVISION=100"
fi

if [ "${DRY_RUN:-0}" != "1" ]; then
    "${SMOKE_CMD:-$SCRIPT_DIR/smoke.sh}"
fi
