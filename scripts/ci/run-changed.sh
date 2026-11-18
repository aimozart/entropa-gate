#!/usr/bin/env bash
# Run the pipeline of every module that changed since <base>, each independently; report all results, fail if any failed.
#   scripts/ci/run-changed.sh [base]      (ALL=1 runs every module)
set -uo pipefail
cd "$(dirname "$0")/../.."
if [ "${ALL:-0}" = 1 ]; then mods=$(jq -r 'keys[]' scripts/ci/modules.json); else mods=$(scripts/ci/changed.sh "${1:-HEAD~1}"); fi
[ -n "$mods" ] || { echo "no module changed: nothing to run"; exit 0; }
fail=0; summary=""
for m in $mods; do
  if scripts/ci/module.sh "$m"; then summary="$summary\n  PASS $m"; else summary="$summary\n  FAIL $m"; fail=1; fi
done
printf 'summary:%b\n' "$summary"; exit $fail
