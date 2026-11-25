#!/usr/bin/env bash
# INS slice 5 mutation run: only the lines changed since the freeze commit (cargo-mutants --in-diff). One job at a time, 6 GB cap, refuses to start under 25 GB free. Usage: scripts/ins2-mutants-4.sh OUT_DIR
set -u
cd "$(dirname "$0")/.."
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9); [ "$free_gb" -ge 25 ] || { echo "refusing to start: only ${free_gb} GB free on / (rule: at least 25 GB)"; exit 3; }
export RUSTUP_TOOLCHAIN=stable CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 TMPDIR=/tmp/tmp-ins2 CARGO_TARGET_DIR=~/.cache/build/ins2-mut-target
mkdir -p "$TMPDIR" "$1"
FREEZE=1fde8213877371bdf4c80d133891f757b4c2b7f4
git diff "$FREEZE" HEAD -- crates/gate/src crates/ledger/src > "$1/changes.diff"
run_one() { # name package tests...
  name=$1; pkg=$2; shift 2
  targs=(); for t in "$@"; do targs+=(--test "$t"); done
  timeout 7200 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue cargo mutants -p "$pkg" --in-diff "$OUTDIR/changes.diff" --test-package "$pkg" --jobs 1 --timeout 120 --build-timeout 900 --output "$OUTDIR/$name" -- "${targs[@]}" > "$OUTDIR/$name.log" 2>&1
  m="$OUTDIR/$name/mutants.out"
  echo "$name: caught $(wc -l < "$m/caught.txt") missed $(wc -l < "$m/missed.txt") timeout $(wc -l < "$m/timeout.txt") unviable $(wc -l < "$m/unviable.txt")"
}
OUTDIR="$1"
run_one gate entropa-gate check_anchor
run_one ledger entropa-ledger strict_lines lower_case raw_reader store_v2
