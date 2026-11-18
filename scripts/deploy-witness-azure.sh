#!/usr/bin/env bash
# Deploy the Entropa checkpoint witness to Azure Container Apps (consumption plan, scale to zero, one replica).
# Everything is created from this file, so it is also the infrastructure-as-code record and the teardown map.
#
#   scripts/deploy-witness-azure.sh plan       print what would be created and the cost estimate (creates nothing)
#   scripts/deploy-witness-azure.sh apply      create it (idempotent; safe to re-run)
#   scripts/deploy-witness-azure.sh evidence   print a redacted resource list for the evidence bundle
#
# Cost (free-trial subscription, spending limit ON): Container Registry Basic about 0.167 USD per day (the image is built locally and pushed: ACR Tasks is blocked on free trials), storage account
# and a 1 GB file share a few cents, Container Apps within its monthly free grant: about 2 to 3 USD until the credit
# expires on 2026-11-16, against 200 USD of credit. Teardown: delete the resource group (the owner's exact word first).
# Needs: az CLI logged in as the Azure account that owns the subscription; the Entropa log public key in LOG_PUBKEY.
set -euo pipefail
cd "$(dirname "$0")/.."
RG=${RG:-entropa-witness-rg}
LOC=${LOC:-westus2}
SUFFIX=${SUFFIX:-$(printf '%s' "$(az account show --query id -o tsv)" | cut -c1-5)}
ACR=${ACR:-entropawit${SUFFIX//-/}}
ST=${ST:-entropawit${SUFFIX//-/}st}
ENVN=entropa-witness-env
APP=entropa-witnessd
SHARE=witness
LOG_PUBKEY=${LOG_PUBKEY:?set LOG_PUBKEY to the hex public key of the ledger to witness (GET /v1/pubkey on the node)}
step=${1:-plan}

if [ "$step" = plan ]; then
  cat <<EOF
Would create in subscription $(az account show --query name -o tsv), region $LOC:
  resource group           $RG
  container registry       $ACR (Basic, about 0.167 USD per day)
  storage account + share  $ST / $SHARE (Standard_LRS, 1 GB; state files only)
  container apps env       $ENVN (consumption, no log analytics)
  container app            $APP (0 to 1 replica, external HTTPS ingress)
Witnesses the log with public key ${LOG_PUBKEY:0:16}..., accepts the first checkpoint on trust (allow_first).
Estimated total until 2026-11-16: about 2 to 3 USD. Teardown: az group delete -n $RG (the owner's exact word first).
EOF
  exit 0
fi

if [ "$step" = evidence ]; then
  az resource list -g "$RG" --query "[].{name:name,type:type,location:location}" -o table
  az containerapp show -g "$RG" -n "$APP" --query "{fqdn:properties.configuration.ingress.fqdn,replicas:properties.template.scale,state:properties.provisioningState}" -o json
  exit 0
fi

[ "$step" = apply ] || { echo "usage: $0 plan|apply|evidence"; exit 2; }

az group create -n "$RG" -l "$LOC" -o none
az acr show -n "$ACR" -g "$RG" -o none 2>/dev/null || az acr create -n "$ACR" -g "$RG" --sku Basic --admin-enabled true -o none
az storage account show -n "$ST" -g "$RG" -o none 2>/dev/null || az storage account create -n "$ST" -g "$RG" -l "$LOC" --sku Standard_LRS --kind StorageV2 --min-tls-version TLS1_2 --allow-blob-public-access false -o none
STKEY=$(az storage account keys list -n "$ST" -g "$RG" --query '[0].value' -o tsv)
az storage share-rm create --storage-account "$ST" -g "$RG" -n "$SHARE" --quota 1 -o none 2>/dev/null || true

# Build the image from a clean source export of the committed code.
SRC=$(mktemp -d "$HOME/.cache/witness-src.XXXXXX")
git archive HEAD | tar -x -C "$SRC"
cp "$SRC/Dockerfile.witnessd" "$SRC/Dockerfile"
# ACR Tasks (az acr build) is not permitted on free-trial subscriptions, so the image is built here and pushed.
docker build -f "$SRC/Dockerfile.witnessd" -t "$ACR.azurecr.io/witnessd:1" "$SRC"
az acr login -n "$ACR" >/dev/null
docker push "$ACR.azurecr.io/witnessd:1"

az containerapp env show -n "$ENVN" -g "$RG" -o none 2>/dev/null || az containerapp env create -n "$ENVN" -g "$RG" -l "$LOC" --logs-destination none -o none
az containerapp env storage set -n "$ENVN" -g "$RG" --storage-name witnessstate --azure-file-account-name "$ST" --azure-file-account-key "$STKEY" --azure-file-share-name "$SHARE" --access-mode ReadWrite -o none

# The witness signing key: generated here, straight into a container-app secret. It is never printed or written to disk.
WKEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
ACRUSER=$(az acr credential show -n "$ACR" --query username -o tsv)
ACRPASS=$(az acr credential show -n "$ACR" --query 'passwords[0].value' -o tsv)
LOGS=$(printf '[{"pubkey_hex":"%s","allow_first":true}]' "$LOG_PUBKEY")
YAML=$(mktemp "$HOME/.cache/witness-app.XXXXXX.yaml")
trap 'rm -f "$YAML"' EXIT
EXISTS=0; az containerapp show -n "$APP" -g "$RG" -o none 2>/dev/null && EXISTS=1
if [ "$EXISTS" = 1 ]; then
  echo "container app exists: updating the image only (the witness key and state are kept)"
  az containerapp update -n "$APP" -g "$RG" --image "$ACR.azurecr.io/witnessd:1" -o none
else
  ENVID=$(az containerapp env show -n "$ENVN" -g "$RG" --query id -o tsv)
  cat > "$YAML" <<EOF
location: $LOC
properties:
  managedEnvironmentId: $ENVID
  configuration:
    ingress:
      external: true
      targetPort: 8080
      transport: auto
    registries:
      - server: $ACR.azurecr.io
        username: $ACRUSER
        passwordSecretRef: acrpass
    secrets:
      - name: acrpass
        value: "$ACRPASS"
      - name: witness-key
        value: "$WKEY"
  template:
    containers:
      - name: witnessd
        image: $ACR.azurecr.io/witnessd:1
        resources:
          cpu: 0.25
          memory: 0.5Gi
        env:
          - name: WITNESS_KEY_FILE
            value: /secrets/key
          - name: WITNESS_STATE_DIR
            value: /state/witness
          - name: WITNESS_LOGS
            value: '$LOGS'
        volumeMounts:
          - volumeName: state
            mountPath: /state
          - volumeName: keyvol
            mountPath: /secrets
    scale:
      minReplicas: 0
      maxReplicas: 1
    volumes:
      - name: state
        storageType: AzureFile
        storageName: witnessstate
      - name: keyvol
        storageType: Secret
        secrets:
          - secretRef: witness-key
            path: key
EOF
  az containerapp create -n "$APP" -g "$RG" --yaml "$YAML" -o none
fi
FQDN=$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
echo "witness URL: https://$FQDN"
echo "witness public key: $(curl -s --max-time 60 "https://$FQDN/v1/pubkey" | cut -c1-64)..."
