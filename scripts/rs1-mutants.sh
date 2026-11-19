#!/usr/bin/env bash
# RS1 mutation run on the NEW code only (flags.rs raw_flags/signals/query_flags_with, rs1eval.rs scorer and runner, the foreign_any_name branch), one job, 6 GB cap.
# Usage: scripts/rs1-mutants.sh OUT_DIR
set -u
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 TMPDIR=~/.cache/build/tmp CARGO_TARGET_DIR=~/.cache/build/rs1-mut-target
mkdir -p "$TMPDIR"
out="$1"
timeout 10800 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
  cargo mutants -p entropa-standards -f crates/standards/src/flags.rs -f crates/standards/src/rs1eval.rs \
  --re 'raw_flags|signals|query_flags_with|classify_injection|score_injection_rs1|inj_block_rs1|load_heldout_rs1|run_heldout_rs1|is_hidden' \
  --jobs 1 --timeout 120 --build-timeout 600 --output "$out" -- --test rs1_raw --test rs1_density --test rs1_scorer --test rs1_runner --test rs1_foreign > "$out.log" 2>&1
m="$out/mutants.out"
echo "caught: $(wc -l < "$m/caught.txt")  missed: $(wc -l < "$m/missed.txt")  timeout: $(wc -l < "$m/timeout.txt")  unviable: $(wc -l < "$m/unviable.txt")"
