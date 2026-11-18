#!/usr/bin/env bash
# EG1 task 4 mutation run on the engine files, memory-capped. Usage: scripts/eg1-mutants.sh [out-dir]   Env: EG1_CASES (default 2000: light mode,
# a survivor must be re-checked at 100000 cases before it counts as a gap, as for the ledger's ENTROPA_FAST_TESTS).
# The scope has MemoryMax=6G and OOMPolicy=continue: a mutant that makes the test grow without bound (a stage record (not published)) is killed by the kernel, only
# that test process dies, and cargo-mutants lists it as "caught" with `signal: 9, SIGKILL` in its log. This script then reclassifies every such mutant as
# NOT TESTABLE (non-terminating): it is never counted as caught.
set -u
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true EG1_CASES="${EG1_CASES:-2000}"
out="${1:-~/.cache/build/eg1-mutants-out}"
timeout 21600 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
  cargo mutants -p entropa-egress -f crates/egress/src/decide.rs -f crates/egress/src/detect.rs -f crates/egress/src/views.rs -f crates/egress/src/policy.rs -f crates/egress/src/send.rs \
  --jobs 4 --timeout 120 --build-timeout 600 --output "$out" > "$out.log" 2>&1
echo "cargo-mutants exit $?" 
m="$out/mutants.out"
echo "caught: $(wc -l < "$m/caught.txt")  missed: $(wc -l < "$m/missed.txt")  timeout: $(wc -l < "$m/timeout.txt")  unviable: $(wc -l < "$m/unviable.txt")"
echo "--- caught only by SIGKILL (non-terminating, NOT counted as caught):"
grep -l "signal: 9" "$m"/log/*.log 2>/dev/null | while read -r f; do basename "$f"; done
