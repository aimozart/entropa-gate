#!/usr/bin/env bash
# Print the modules whose paths changed since a base commit (default: the previous commit). Used to run only what changed.
#   scripts/ci/changed.sh [base]
set -euo pipefail
cd "$(dirname "$0")/../.."
base=${1:-HEAD~1}
files=$(git diff --name-only "$base" HEAD)
# a change to the lockfile or the workspace manifest touches every module
if printf '%s\n' "$files" | grep -qE '^(Cargo\.toml|Cargo\.lock|rust-toolchain)'; then jq -r 'keys[]' scripts/ci/modules.json; exit 0; fi
for m in $(jq -r 'keys[]' scripts/ci/modules.json); do
  for p in $(jq -r --arg m "$m" '.[$m].paths[]' scripts/ci/modules.json); do
    if printf '%s\n' "$files" | grep -q "^$p"; then echo "$m"; break; fi
  done
done
