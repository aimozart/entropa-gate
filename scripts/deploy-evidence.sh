#!/usr/bin/env bash
# Record a deploy as audit evidence (a signed, hash-only change/deploy event) on the local evidence node.
#   scripts/deploy-evidence.sh "cloud-run entropa-platinum revision 00005-xyz"
# Best effort: a missing node never fails a deploy. Counts and ids only; the argument is hashed and dropped.
set -uo pipefail
DIR=${EVIDENCE_DIR:-$HOME/.local/share/hippagrchealthcare-evidence}
detail=${1:-deploy}
command -v entropa-platinum >/dev/null && { [ -f "$DIR/evidence.key" ] || [ -f "$DIR/platinum.key" ]; } || exit 0
run="deploy-$(date +%Y%m%d%H%M%S)"
jq -n --arg d "$detail" --arg r "$run" '{kind:"evidence.change",label:"deploy",decision:"info",reason:"check_passed",control:"hitrust_10_sdlc",total:1,passed:1,flagged:0,detail:$d,run_id:$r}' \
  | entropa-platinum log-evidence "$DIR" >/dev/null 2>&1 || true
exit 0
