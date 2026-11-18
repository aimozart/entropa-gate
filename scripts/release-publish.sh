#!/usr/bin/env bash
# Publish entropa-core then entropa-kms to crates.io (cargo orders them by dependency and waits for
# the index). Needs CARGO_REGISTRY_TOKEN in the environment: in CI it is the short-lived token
# minted by crates.io Trusted Publishing; this script never stores or prints it.
# Use DRY_RUN=1 to package and verify without uploading.
set -euo pipefail
source "$(dirname "$0")/lib-docker.sh"
flags=(--locked -p entropa-core -p entropa-kms)
if [ "${DRY_RUN:-0}" = "1" ]; then
  in_dev cargo publish --dry-run "${flags[@]}"
else
  : "${CARGO_REGISTRY_TOKEN:?CARGO_REGISTRY_TOKEN is required (Trusted Publishing token)}"
  IN_DEV_PASS_ENV="CARGO_REGISTRY_TOKEN" in_dev cargo publish "${flags[@]}"
fi
