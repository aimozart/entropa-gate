#!/usr/bin/env bash
# S0i: the mutation runner's defaults (checked with the dry-run mode, nothing is executed).
#   - 4 jobs by default; ENTROPA_MUTANTS_JOBS beats JOBS beats the default
#   - a lighter test mode (ENTROPA_FAST_TESTS=1) is passed into the container for mutation runs only
#   - the standard gates (check.sh, count-tests.sh) never set it
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
run() { env "$@" ENTROPA_DEV_DRY_RUN=1 scripts/mutants.sh entropa-ledger 2>&1; }
has() { case "$1" in *"$2"*) ok "$3";; *) bad "$3 (wanted: $2)";; esac; }

out="$(env -u JOBS -u ENTROPA_MUTANTS_JOBS -u ENTROPA_FAST_TESTS ENTROPA_DEV_DRY_RUN=1 scripts/mutants.sh entropa-ledger 2>&1)"
has "$out" "--jobs 4"                 "default is 4 jobs"
has "$out" "--timeout 30"             "default timeout is 30 s"
has "$out" "fast_tests=1"             "the fast test mode is on by default for mutation runs"
has "$out" "-e ENTROPA_FAST_TESTS"    "the fast-test variable is passed into the container"
has "$out" "memory=24g"               "the container limits are still printed"
has "$(run JOBS=3)" "--jobs 3"                           "JOBS overrides the default"
has "$(run JOBS=3 ENTROPA_MUTANTS_JOBS=2)" "--jobs 2"    "ENTROPA_MUTANTS_JOBS beats JOBS"
has "$(run ENTROPA_FAST_TESTS=0)" "fast_tests=0"         "ENTROPA_FAST_TESTS=0 turns the light mode off (full-strength tests)"

for f in scripts/check.sh scripts/count-tests.sh scripts/ci.sh; do
  if grep -q "ENTROPA_FAST_TESTS" "$f"; then bad "$f must not set the fast test mode"; else ok "$f does not set the fast test mode"; fi
done
exit $fail
