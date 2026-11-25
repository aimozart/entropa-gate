#!/usr/bin/env bash
# INS2 mutation run on the anchor, anchor-file, raw-reader and check modules: one job at a time, 6 GB cap, refuses to start under 25 GB free. Usage: scripts/ins2-mutants.sh OUT_DIR
set -u
cd "$(dirname "$0")/.."
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9); [ "$free_gb" -ge 25 ] || { echo "refusing to start: only ${free_gb} GB free on / (rule: at least 25 GB)"; exit 3; }
export RUSTUP_TOOLCHAIN=stable CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 TMPDIR=/tmp/tmp-ins2 CARGO_TARGET_DIR=~/.cache/build/ins2-mut-target
mkdir -p "$TMPDIR" "$1"
run() { # name, package, file, test-package, test-name
  timeout 7200 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
    cargo mutants -p "$2" --file "$3" --test-package "$4" --jobs 1 --timeout 120 --build-timeout 900 --output "$1/$5" -- --test "$6" > "$1/$5.log" 2>&1
  m="$1/$5/mutants.out"
  echo "$5: caught $(wc -l < "$m/caught.txt") missed $(wc -l < "$m/missed.txt") timeout $(wc -l < "$m/timeout.txt") unviable $(wc -l < "$m/unviable.txt")"
}
OUT="$1"
run_in() { :; }
run_one() { OUTBASE="$OUT"; timeout 7200 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue cargo mutants -p "$2" --file "$3" --test-package "$4" --jobs 1 --timeout 120 --build-timeout 900 --output "$OUT/$1" -- --test "$5" > "$OUT/$1.log" 2>&1; m="$OUT/$1/mutants.out"; echo "$1: caught $(wc -l < "$m/caught.txt") missed $(wc -l < "$m/missed.txt") timeout $(wc -l < "$m/timeout.txt") unviable $(wc -l < "$m/unviable.txt")"; }
run_one core-anchor entropa-core crates/core/src/anchor.rs entropa-core anchor
run_one witness-anchor-file entropa-witness crates/witness/src/anchor_file.rs entropa-witness anchor_file
run_one ledger-raw entropa-ledger crates/ledger/src/raw.rs entropa-ledger raw_reader
run_one gate-check entropa-gate crates/gate/src/check.rs entropa-gate check_anchor
