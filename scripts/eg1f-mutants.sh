#!/usr/bin/env bash
# EG1f mutation run on the NEW files only (context.rs, contain.rs, v2.rs), one job, 6 GB cap, SIGKILL mutants reclassified NOT TESTABLE.
# Usage: scripts/eg1f-mutants.sh OUT_DIR [REGEX]   Tests used: the fast sample tests plus the context and containment units (x4 and x5 (full DEV sets, too slow in debug) are skipped and run separately).
set -u
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 TMPDIR=~/.cache/build/tmp CARGO_TARGET_DIR=~/.cache/build/eg1f-mut-target
mkdir -p "$TMPDIR"
out="$1"; shift
extra=(); [ $# -ge 1 ] && extra=(--re "$1")
timeout 21600 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
  cargo mutants -p entropa-egress -f crates/egress/src/context.rs -f crates/egress/src/contain.rs -f crates/egress/src/v2.rs "${extra[@]}" \
  --jobs 1 --timeout 120 --build-timeout 600 --output "$out" -- --test eg1f_fast --test eg1f_context --test eg1f_contain --test eg1f_units --test eg1f_units_v2 -- --skip x4_ --skip x5_ > "$out.log" 2>&1
m="$out/mutants.out"
echo "caught: $(wc -l < "$m/caught.txt")  missed: $(wc -l < "$m/missed.txt")  timeout: $(wc -l < "$m/timeout.txt")  unviable: $(wc -l < "$m/unviable.txt")"
echo "--- caught only by SIGKILL (NOT counted as caught):"; grep -l "signal: 9" "$m"/log/*.log 2>/dev/null | while read -r f; do basename "$f"; done
