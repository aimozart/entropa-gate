#!/usr/bin/env bash
# Fuzz smoke. Usage: [FUZZ_CRATE=core|mcp|...] scripts/fuzz.sh [target] [seconds]   (default: core, every target, 30s each)
# Limits: the container limits from lib-docker.sh plus libFuzzer's own -rss_limit_mb (FUZZ_RSS_MB, default 4096).
set -euo pipefail
source "$(dirname "$0")/lib-docker.sh"
secs="${2:-30}"
rss="${FUZZ_RSS_MB:-4096}"
echo "fuzz: rss_limit_mb=$rss $(dev_limits)" >&2
targets=("${1:-}"); [ -n "${targets[0]}" ] || mapfile -t targets < <(in_dev bash -c 'cd crates/${FUZZ_CRATE:-core} && cargo +nightly fuzz list')
for t in "${targets[@]}"; do
  echo "== fuzz $t for ${secs}s"
  in_dev bash -c "cd crates/${FUZZ_CRATE:-core} && cargo +nightly fuzz run $t -- -max_total_time=$secs -rss_limit_mb=$rss"
done
