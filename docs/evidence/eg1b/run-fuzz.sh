#!/usr/bin/env bash
# EG1 task 4 fuzz run: each target under a 6 GB cgroup cap with libFuzzer's own rss limit and a wall-clock timeout. Output to docs/evidence/eg1b/fuzz-<target>.txt
set -u
cd "$(dirname "$0")/../../../crates/egress/fuzz"
export CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="<build-dir>/eg1-fuzz-target"
for spec in decide_request:300 detect_scan:300 views_spans:120 policy_parse:120; do
  t=${spec%%:*}; s=${spec##*:}
  timeout $((s+300)) systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 \
    cargo +nightly fuzz run "$t" "seeds/$t" -- -max_total_time="$s" -rss_limit_mb=2048 > "../../../docs/evidence/eg1b/fuzz-$t.txt" 2>&1
  echo "$t exit $?" >> ../../../docs/evidence/eg1b/fuzz-summary.txt
done
