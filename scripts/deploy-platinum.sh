#!/usr/bin/env bash
# Deploy the platinum ingest to Cloud Run in project entropa-testnet. Serverless, scale to zero, ONE instance (single writer).
# Cost: Cloud Run free tier, bucket cents, Secret Manager 0.06 USD/month, image under the free 0.5 GB.
# Teardown (needs the owner's exact word + yes/no): scripts/teardown-platinum.sh
# Steps marked [IAM] are run by the owner (the assistant's permission classifier blocks IAM grants).
set -euo pipefail
P=entropa-testnet; R=us-central1; SVC=entropa-platinum; SA=entropa-platinum-run
BUCKET=${P}-platinum-ledger; REPO=entropa; IMG=$R-docker.pkg.dev/$P/$REPO/$SVC:latest; SECRET=entropa-platinum-key
cd "$(dirname "$0")/.."
step=${1:-all}

if [ "$step" = resources ] || [ "$step" = all ]; then
  gcloud storage buckets describe "gs://$BUCKET" --project $P >/dev/null 2>&1 || \
    gcloud storage buckets create "gs://$BUCKET" --project $P --location $R --uniform-bucket-level-access --public-access-prevention
  gcloud artifacts repositories describe $REPO --location $R --project $P >/dev/null 2>&1 || \
    gcloud artifacts repositories create $REPO --repository-format docker --location $R --project $P
  if ! gcloud secrets describe $SECRET --project $P >/dev/null 2>&1; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | gcloud secrets create $SECRET --project $P --data-file=-
  fi
  echo "resources ok"
fi
if [ "$step" = iam ] || [ "$step" = all ]; then   # [IAM]
  gcloud iam service-accounts describe "$SA@$P.iam.gserviceaccount.com" --project $P >/dev/null 2>&1 || \
    gcloud iam service-accounts create $SA --project $P --display-name "Entropa platinum ingest (runtime)"
  gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member "serviceAccount:$SA@$P.iam.gserviceaccount.com" --role roles/storage.objectUser >/dev/null
  gcloud secrets add-iam-policy-binding $SECRET --project $P --member "serviceAccount:$SA@$P.iam.gserviceaccount.com" --role roles/secretmanager.secretAccessor >/dev/null
  echo "iam ok"
fi
if [ "$step" = build ] || [ "$step" = all ]; then
  src=$(mktemp -d "$HOME/.cache/platinum-src.XXXXXX")
  git archive HEAD | tar -x -C "$src"
  cp "$src/Dockerfile.platinum" "$src/Dockerfile"
  gcloud builds submit "$src" --project $P --region $R --tag "$IMG"
  echo "built $IMG (source copy in $src)"
fi
if [ "$step" = deploy ] || [ "$step" = all ]; then
  gcloud run deploy $SVC --project $P --region $R --image "$IMG" \
    --service-account "$SA@$P.iam.gserviceaccount.com" --no-allow-unauthenticated \
    --min-instances 0 --max-instances 1 --concurrency 8 --cpu 1 --memory 512Mi --timeout 60 \
    --add-volume name=ledger,type=cloud-storage,bucket=$BUCKET \
    --add-volume-mount volume=ledger,mount-path=/data \
    --clear-secrets --set-env-vars ENTROPA_GCP_KMS_KEY=projects/$P/locations/$R/keyRings/entropa/cryptoKeys/entropa-ledger-signer/cryptoKeyVersions/1
  "$(dirname "$0")/deploy-evidence.sh" "cloud-run entropa-platinum deploy $(date -u +%FT%TZ)" || true
fi
# Run order: resources, iam, build, deploy (or 'all').
