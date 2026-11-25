#!/usr/bin/env bash
# TH1 mutation run on the entropa-check core, one job, 6 GB cap, refuses to start under 25 GB free. Usage: scripts/th1-mutants.sh OUT_DIR
set -u
cd "$(dirname "$0")/.."
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9); [ "$free_gb" -ge 25 ] || { echo "refusing to start: only ${free_gb} GB free on / (rule: at least 25 GB)" >&2; exit 1; }
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 TMPDIR=/tmp/tmp-th1 CARGO_TARGET_DIR=~/.cache/build/th1-mut-target
mkdir -p "$TMPDIR"
out="$1"
timeout 14400 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
  cargo mutants -p entropa-check --jobs 1 --timeout 90 --build-timeout 600 --output "$out" -- --tests > "$out.log" 2>&1
m="$out/mutants.out"
echo "caught: $(wc -l < "$m/caught.txt")  missed: $(wc -l < "$m/missed.txt")  timeout: $(wc -l < "$m/timeout.txt")  unviable: $(wc -l < "$m/unviable.txt")"
