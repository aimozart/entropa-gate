#!/usr/bin/env bash
# Re-run a SUBSET of the engine mutants (regex on "file:line:col: replace ... in fn"), same cap and SIGKILL reclassification as scripts/eg1-mutants.sh.
# Usage: scripts/eg1-mutants-subset.sh OUT_DIR REGEX   (EG1_CASES defaults to 2000)
set -u
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true EG1_CASES="${EG1_CASES:-2000}" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"  # many test binaries are built per mutant: unlimited build jobs exceeded the 6 GB cap (compiler SIGKILLed, reported as unviable)
out="$1"; re="$2"
timeout 14400 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 -p OOMPolicy=continue \
  cargo mutants -p entropa-egress -f crates/egress/src/decide.rs -f crates/egress/src/detect.rs -f crates/egress/src/views.rs -f crates/egress/src/policy.rs -f crates/egress/src/send.rs \
  --re "$re" --jobs "${MUTANT_JOBS:-2}" --timeout 120 --build-timeout 600 --output "$out" > "$out.log" 2>&1
m="$out/mutants.out"
echo "caught: $(wc -l < "$m/caught.txt")  missed: $(wc -l < "$m/missed.txt")  timeout: $(wc -l < "$m/timeout.txt")  unviable: $(wc -l < "$m/unviable.txt")"
echo "--- caught only by SIGKILL (NOT counted as caught):"; grep -l "signal: 9" "$m"/log/*.log 2>/dev/null | while read -r f; do basename "$f"; done
echo "--- missed:"; cat "$m/missed.txt"
