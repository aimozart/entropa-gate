#!/usr/bin/env bash
# BV1: the verification code must build for wasm32-unknown-unknown WITHOUT any randomness source (no getrandom, no rand), offline and locked.
# Uses the `stable` toolchain (same rustc as the pinned one) because that is where the wasm32 target is installed. Usage: scripts/tests/wasm-verify-build.sh [crate ...] (default: entropa-core)
set -u
cd "$(dirname "$0")/../.."
export RUSTUP_TOOLCHAIN=stable CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/build/bv1-target}" TMPDIR="${TMPDIR:-/tmp/tmp-bv1}"
mkdir -p "$TMPDIR"
crates=("$@"); [ ${#crates[@]} -gt 0 ] || crates=(entropa-core)
rc=0
for c in "${crates[@]}"; do
  if cargo build --release --offline --locked --target wasm32-unknown-unknown -p "$c" --no-default-features >"$TMPDIR/b-$c.log" 2>&1; then echo "OK   build $c (wasm32, no default features)"; else echo "FAIL build $c: $(grep -m1 '^error' "$TMPDIR/b-$c.log")"; rc=1; fi
  t=$(cargo tree --offline --locked -p "$c" --no-default-features -e normal --target wasm32-unknown-unknown 2>&1)
  if echo "$t" | grep -E -q "getrandom|rand_core|rand v|^error"; then echo "FAIL tree $c: $(echo "$t" | grep -E -m2 'getrandom|rand|^error' | tr '\n' ' ')"; rc=1; else echo "OK   tree $c has no getrandom or rand"; fi
done
exit $rc
