#!/usr/bin/env bash
# Mutation testing. Usage: scripts/mutants.sh [crate ...]  (default: entropa-core entropa-kms)
set -euo pipefail
source "$(dirname "$0")/lib-docker.sh"
pkgs=("$@"); [ ${#pkgs[@]} -gt 0 ] || pkgs=(entropa-core entropa-kms)
args=(); for p in "${pkgs[@]}"; do args+=(--package "$p"); done
# CARGO_TARGET_DIR must be unset: parallel jobs sharing one target dir clobber each other's mutated builds (flaky MISSED results seen on 2026-10-20).
# Jobs: ENTROPA_MUTANTS_JOBS, else JOBS, else 4 (peak RAM was about 10 GiB with 2 jobs; check it stays under the container cap, raise
# ENTROPA_DEV_MEMORY if not). Timeout: ENTROPA_MUTANTS_TIMEOUT, else MUTANTS_TIMEOUT, else 30 s. The container limits come from lib-docker.sh.
# Light test mode: ENTROPA_FAST_TESTS=1 (default here, mutation runs ONLY; check.sh and CI never set it) is read by the test helpers of the crates
# that support it (today: entropa-ledger) to use fewer scenarios and proptest cases with the same assertions. A survivor found in the light mode must
# be re-checked with ENTROPA_FAST_TESTS=0 before it counts as a gap (the light mode can only add survivors, never hide one).
jobs="${ENTROPA_MUTANTS_JOBS:-${JOBS:-4}}"
timeout_s="${ENTROPA_MUTANTS_TIMEOUT:-${MUTANTS_TIMEOUT:-30}}"
export ENTROPA_FAST_TESTS="${ENTROPA_FAST_TESTS:-1}"
echo "mutants: jobs=$jobs timeout=${timeout_s}s fast_tests=$ENTROPA_FAST_TESTS $(dev_limits)" >&2
IN_DEV_PASS_ENV="ENTROPA_FAST_TESTS" in_dev env -u CARGO_TARGET_DIR cargo mutants "${args[@]}" --jobs "$jobs" --timeout "$timeout_s" --output /work/target/mutants
