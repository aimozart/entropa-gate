#!/usr/bin/env bash
# Per-module pipeline: fmt, clippy -D warnings and tests for ONE module's packages, then a signed evidence receipt
# (counts only) in the local evidence ledger. Independent of every other module.
#   scripts/ci/module.sh <module>          modules are listed in scripts/ci/modules.json
# Exit code is the module's own result. The receipt step is best effort and never changes the exit code.
set -uo pipefail
cd "$(dirname "$0")/../.."
mod=${1:?module name (see scripts/ci/modules.json)}
pkgs=$(jq -r --arg m "$mod" '.[$m].packages // empty | join(" ")' scripts/ci/modules.json)
[ -n "$pkgs" ] || { echo "unknown module: $mod"; exit 2; }
args=""; for p in $pkgs; do args="$args -p $p"; done
sha=$(git rev-parse --short=12 HEAD 2>/dev/null || echo nogit)
rc=0; passed=0; failed=0
echo "== $mod ($pkgs) at $sha"
cargo fmt $args -- --check >/dev/null 2>&1 || { echo "fmt FAILED"; rc=1; }
cargo clippy $args --all-targets --locked -- -D warnings >/dev/null 2>&1 || { echo "clippy FAILED"; rc=1; }
out=$(cargo test $args --locked 2>&1); t_rc=$?
passed=$(printf '%s' "$out" | grep -Eo '[0-9]+ passed' | grep -Eo '[0-9]+' | paste -sd+ | bc 2>/dev/null || echo 0); passed=${passed:-0}
failed=$(printf '%s' "$out" | grep -Eo '[0-9]+ failed' | grep -Eo '[0-9]+' | paste -sd+ | bc 2>/dev/null || echo 0); failed=${failed:-0}
[ "$t_rc" -eq 0 ] || rc=1
echo "tests: $passed passed, $failed failed; result: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
# signed receipt: evidence.control_check / ci_tests, counts only (the module name and sha are hashed with the run id, never stored)
DIR=${EVIDENCE_DIR:-$HOME/.local/share/hippagrchealthcare-evidence}
if command -v entropa-platinum >/dev/null && { [ -f "$DIR/evidence.key" ] || [ -f "$DIR/platinum.key" ]; }; then
  if [ "$rc" -eq 0 ]; then d=allow; r=check_passed; else d=deny; r=check_failed; fi
  jq -n --arg d "$d" --arg r "$r" --argjson t $((passed + failed)) --argjson p "$passed" --argjson f "$failed" --arg det "module $mod at $sha" --arg run "ci-$mod-$sha" \
    '{kind:"evidence.control_check",label:"ci_tests",decision:$d,reason:$r,control:"hitrust_10_sdlc",total:$t,passed:$p,flagged:$f,detail:$det,run_id:$run}' \
    | entropa-platinum log-evidence "$DIR" >/dev/null 2>&1 && echo "receipt recorded (ci-$mod-$sha)" || echo "(receipt not recorded)"
fi
exit $rc
