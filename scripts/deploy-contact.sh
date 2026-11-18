#!/usr/bin/env bash
# Deploy the contact-form service to Cloud Run (entropa-testnet): serverless, scale to zero, one instance.
# Cost: free tier (a handful of requests a month). Needs the existing service account entropa-gmail-ops and
# secret entropa-gmail-sa-key (already used by bigiron-contact). The inbox address lives only in the env var.
# Steps: build | deploy | public (allows the website to call it; an IAM change run by the owner) | all
set -euo pipefail
cd "$(dirname "$0")/.."
P=entropa-testnet; R=us-central1; SVC=entropa-contact
IMG=$R-docker.pkg.dev/$P/entropa/$SVC:latest
step=${1:-all}
if [ "$step" = build ] || [ "$step" = all ]; then
  src=$(mktemp -d "$HOME/.cache/contact-src.XXXXXX")
  git archive HEAD | tar -x -C "$src"
  cp "$src/Dockerfile.contact" "$src/Dockerfile"
  gcloud builds submit "$src" --project $P --region $R --tag "$IMG"
fi
if [ "$step" = deploy ] || [ "$step" = all ]; then
  gcloud run deploy $SVC --project $P --region $R --image "$IMG" \
    --service-account "entropa-gmail-ops@$P.iam.gserviceaccount.com" \
    --min-instances 0 --max-instances 1 --concurrency 10 --cpu 1 --memory 256Mi --timeout 30 \
    --clear-secrets \
    --set-env-vars GMAIL_SENDER=aimozart@entropa.space,CONTACT_TO=contact@example.invalid \
    --allow-unauthenticated
  "$(dirname "$0")/deploy-evidence.sh" "cloud-run entropa-contact deploy $(date -u +%FT%TZ)" || true
fi
