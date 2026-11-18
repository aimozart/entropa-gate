#!/usr/bin/env bash
# AT2 task 1: mutation run of the token crate (285 mutants), one at a time under the 6 GB cap, release-profile tests, light property mode (AT1_CASES=1000),
# non-terminating mutants SIGKILLed alone and reported separately. Usage: scripts/at2-tokens-mutants.sh OUT_DIR
set -u
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true AT1_CASES="${AT1_CASES:-1000}" CARGO_BUILD_JOBS=2
out="$1"; mkdir -p "$out"
timeout 21600 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
  cargo mutants -p entropa-tokens -f crates/tokens/src/canon.rs -f crates/tokens/src/verify.rs -f crates/tokens/src/design_a.rs -f crates/tokens/src/revoke.rs -f crates/tokens/src/claims.rs \
  --jobs 1 --timeout 600 --build-timeout 900 --output "$out" -- --release > "$out.log" 2>&1
m="$out/mutants.out"
echo "caught $(wc -l < "$m/caught.txt") missed $(wc -l < "$m/missed.txt") timeout $(wc -l < "$m/timeout.txt") unviable $(wc -l < "$m/unviable.txt")"
echo "--- SIGKILL (not counted as caught):"; grep -l "signal: 9" "$m"/log/*.log 2>/dev/null | while read -r f; do basename "$f"; done
echo "--- missed:"; cat "$m/missed.txt"; echo "--- timeout:"; cat "$m/timeout.txt"
