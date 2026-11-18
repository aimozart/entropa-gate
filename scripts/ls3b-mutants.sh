#!/usr/bin/env bash
# LS3b mutation run on the new code (lib.rs, server.rs, settings.rs of crates/try-http), one job, 6 GB cap, SIGKILL mutants listed. Usage: scripts/ls3b-mutants.sh OUT_DIR [REGEX]
set -u
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 TMPDIR=~/.cache/build/tmp CARGO_TARGET_DIR=~/.cache/build/ls3b-mut-target
mkdir -p "$TMPDIR"
out="$1"; shift
extra=(); [ $# -ge 1 ] && extra=(--re "$1")
timeout 21600 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
  cargo mutants -p entropa-try-http -f crates/try-http/src/lib.rs -f crates/try-http/src/server.rs -f crates/try-http/src/settings.rs "${extra[@]}" \
  --jobs 1 --timeout 90 --build-timeout 600 --output "$out" > "$out.log" 2>&1
m="$out/mutants.out"
echo "caught: $(wc -l < "$m/caught.txt")  missed: $(wc -l < "$m/missed.txt")  timeout: $(wc -l < "$m/timeout.txt")  unviable: $(wc -l < "$m/unviable.txt")"
echo "--- caught only by SIGKILL (NOT counted as caught):"; grep -l "signal: 9" "$m"/log/*.log 2>/dev/null | while read -r f; do basename "$f"; done
