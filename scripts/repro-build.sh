#!/usr/bin/env bash
# S2d: build the gate binary twice in two fresh containers (no network) from `git archive` of the SAME commit and compare the sha256.
# Usage: scripts/repro-build.sh [package] [bin]   Output dir: $REPRO_OUT (default ~/.cache/build/repro). Nothing is deleted.
set -euo pipefail
pkg="${1:-entropa-gate}"; bin="${2:-entropa-gate}"
root="$(cd "$(dirname "$0")/.." && pwd)"; out="${REPRO_OUT:-$HOME/.cache/build/repro}/$(git -C "$root" rev-parse --short=12 HEAD)-$(date +%s)"
mkdir -p "$out"; image="${ENTROPA_DEV_IMAGE:-entropa-dev:1}"
epoch=$(git -C "$root" log -1 --format=%ct)
for n in 1 2; do
  mkdir -p "$out/src$n" "$out/target$n"; git -C "$root" archive HEAD | tar -x -C "$out/src$n"
  docker run --rm --network none --memory=6g --memory-swap=6g --cpus=2 --pids-limit=4096 --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target -e SOURCE_DATE_EPOCH="$epoch" -e CARGO_NET_OFFLINE=true \
    -e RUSTFLAGS="--remap-path-prefix=/work=/src --remap-path-prefix=/cargo=/cargo --remap-path-prefix=/target=/target" \
    -e CARGO_PROFILE_RELEASE_DEBUG=0 -e "PATH=/cargo/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    -v "$HOME/.cargo/registry":/cargo/registry:ro \
    -v "$out/src$n":/work -v "$out/target$n":/target -w /work "$image" \
    cargo build --release --locked --offline -p "$pkg" --bin "$bin" 2>&1 | tail -3 | sed "s/^/[build $n] /"
  cp "$out/target$n/release/$bin" "$out/$bin.$n"
done
echo "output: $out"
"$root/scripts/repro-compare.sh" "$out/$bin.1" "$out/$bin.2" | tee "$out/result.txt"
