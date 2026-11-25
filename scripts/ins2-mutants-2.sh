#!/usr/bin/env bash
# INS2 mutation run 2: the v2 parts of the store and the v2 writer, plus the per-kind verification in nodecore. One job at a time, 6 GB cap, refuses to start under 25 GB free. Usage: scripts/ins2-mutants-2.sh OUT_DIR
set -u
cd "$(dirname "$0")/.."
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9); [ "$free_gb" -ge 25 ] || { echo "refusing to start: only ${free_gb} GB free on / (rule: at least 25 GB)"; exit 3; }
export RUSTUP_TOOLCHAIN=stable CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 TMPDIR=/tmp/tmp-ins2 CARGO_TARGET_DIR=~/.cache/build/ins2-mut-target
mkdir -p "$TMPDIR" "$1"
OUT="$1"
run_one() { # name package file test-package test-name regex
  timeout 7200 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue cargo mutants -p "$2" --file "$3" --examine-re "$6" --test-package "$4" --jobs 1 --timeout 120 --build-timeout 900 --output "$OUT/$1" -- --test "$5" > "$OUT/$1.log" 2>&1
  m="$OUT/$1/mutants.out"; echo "$1: caught $(wc -l < "$m/caught.txt") missed $(wc -l < "$m/missed.txt") timeout $(wc -l < "$m/timeout.txt") unviable $(wc -l < "$m/unviable.txt")"
}
run_one ledger-store-v2 entropa-ledger crates/ledger/src/store.rs entropa-ledger store_v2 'check_parts|check_checkpoint|check_checkpoint_v2|view|put_checkpoint_v2|any_checkpoints|load'
run_one nodecore-v2 entropa-nodecore crates/nodecore/src/lib.rs entropa-nodecore v2 'append_v2|verify_ledger|append'
