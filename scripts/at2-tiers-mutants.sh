#!/usr/bin/env bash
# AT2 task 6: mutation testing of entropa-tiers (lib.rs, cedar.rs), one mutant at a time under the 6 GB cap, release-profile tests, AT2_CASES=1000 for the property test.
# Non-terminating mutants are SIGKILLed alone and reported separately (never counted as caught). Usage: scripts/at2-tiers-mutants.sh OUT_DIR
set -u
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true AT2_CASES="${AT2_CASES:-1000}" CARGO_BUILD_JOBS=2
out="$1"; mkdir -p "$out"
timeout 14400 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
  cargo mutants -p entropa-tiers -f crates/tiers/src/lib.rs -f crates/tiers/src/cedar.rs --jobs 1 --timeout 300 --build-timeout 900 --output "$out" -- --release > "$out.log" 2>&1
m="$out/mutants.out"
echo "caught $(wc -l < "$m/caught.txt") missed $(wc -l < "$m/missed.txt") timeout $(wc -l < "$m/timeout.txt") unviable $(wc -l < "$m/unviable.txt")"
echo "--- SIGKILL (not counted as caught):"; grep -l "signal: 9" "$m"/log/*.log 2>/dev/null | while read -r f; do basename "$f"; done
echo "--- missed:"; cat "$m/missed.txt"; echo "--- timeout:"; cat "$m/timeout.txt"
