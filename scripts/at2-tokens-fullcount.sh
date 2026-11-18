#!/usr/bin/env bash
# AT2 task 1: the token crate's full suite at the full property case counts (100,000 per property), release then debug, each under the 6 GB cap.
# Output: docs/evidence/at2/tokens-full-release.txt and tokens-full-debug.txt
set -u
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true
for m in --release ""; do
  name=$([ -z "$m" ] && echo debug || echo release)
  timeout 7200 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 cargo test $m --offline -p entropa-tokens -j2 2>&1 | grep -E "^test result|FAILED|panicked|running [0-9]+ test|Running" > docs/evidence/at2/tokens-full-$name.txt
done
echo FINISHED > docs/evidence/at2/tokens-full-finished.txt
