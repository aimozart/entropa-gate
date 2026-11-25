#!/usr/bin/env bash
# KEYS1 mutation run on the new key-selection code in crates/platinum/src/lib.rs, one job, 6 GB cap. Usage: scripts/keys1-mutants.sh OUT_DIR
set -u
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 TMPDIR=~/.cache/build/tmp CARGO_TARGET_DIR=~/.cache/build/keys1-mut-target
mkdir -p "$TMPDIR"
out="$1"
timeout 3000 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
  cargo mutants -p entropa-platinum -f crates/platinum/src/lib.rs \
  --re 'keys_check|keys_add|write_new_key|key_location|read_probe|load_probe_for|node_signer_for|Ledger|init|legacy_path' \
  --jobs 1 --timeout 120 --build-timeout 600 --output "$out" -- --test keys1 > "$out.log" 2>&1
m="$out/mutants.out"
echo "caught: $(wc -l < "$m/caught.txt")  missed: $(wc -l < "$m/missed.txt")  timeout: $(wc -l < "$m/timeout.txt")  unviable: $(wc -l < "$m/unviable.txt")"
