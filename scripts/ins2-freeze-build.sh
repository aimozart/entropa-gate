#!/usr/bin/env bash
# INS freeze build: the release binary `entropa-gate` built TWICE inside a build container with NO network (rust:1.99.1-bookworm, already on this machine), source mounted at /src, static glibc,
# no build id, symbols stripped, paths remapped; the two SHA-256 values must be equal. Same method as scripts/ls3c-package.sh. Nothing is pulled, pushed or deleted; containers are named and left stopped.
# Usage: scripts/ins2-freeze-build.sh [OUT_DIR]   (default ~/.cache/build/ins2-freeze). The source is the CURRENT worktree: run it on a clean checkout of the freeze commit.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="$PWD"
OUT="${1:-$HOME/.cache/build/ins2-freeze}"
BUILDER="${INS2_BUILDER:-rust:1.99.1-bookworm}"
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "refused: the worktree has uncommitted changes" >&2; exit 2; }
mkdir -p "$OUT"
docker image inspect "$BUILDER" >/dev/null 2>&1 || { echo "the build image $BUILDER is not on this machine (nothing is pulled)" >&2; exit 1; }
CARGO_HOME_DIR="${INS2_CARGO_HOME:-$HOME/.cache/build/ls3c-package/ls3c-cargo-home}"
[ -d "$CARGO_HOME_DIR/registry" ] || { echo "no cargo registry copy at $CARGO_HOME_DIR (copy ~/.cargo/registry there first)" >&2; exit 1; }
stamp=$(date +%Y%m%dT%H%M%S)
build() { # $1 = target dir of this build, $2 = where to put the binary
  mkdir -p "$1"
  timeout 3000 docker run --name "ins2-freeze-$stamp-$(basename "$1")" --network none --memory 6g --memory-swap 6g --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e RUSTUP_TOOLCHAIN=1.99.1-x86_64-unknown-linux-gnu -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target -e CARGO_NET_OFFLINE=true -e SOURCE_DATE_EPOCH=1700000000 \
    -e CARGO_PROFILE_RELEASE_STRIP=symbols -e CARGO_PROFILE_RELEASE_DEBUG=0 \
    -e RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--build-id=none --remap-path-prefix=/src=/src --remap-path-prefix=/cargo=/cargo" \
    -v "$SRC":/src:ro -v "$CARGO_HOME_DIR":/cargo -v "$1":/target -w /src "$BUILDER" \
    cargo build --release --locked --offline -j2 -p entropa-gate --bin entropa-gate --target x86_64-unknown-linux-gnu
  cp "$1/x86_64-unknown-linux-gnu/release/entropa-gate" "$2"
}
echo "== build 1" >&2; build "$OUT/target-$stamp-1" "$OUT/entropa-gate"
echo "== build 2 (a different target directory)" >&2; build "$OUT/target-$stamp-2" "$OUT/entropa-gate.second"
A=$(sha256sum "$OUT/entropa-gate" | cut -d' ' -f1); B=$(sha256sum "$OUT/entropa-gate.second" | cut -d' ' -f1)
{
  echo "freeze build ($stamp)"; echo "commit: $(git rev-parse HEAD)"; echo "builder image: $BUILDER ($(docker image inspect --format '{{.Id}}' "$BUILDER"))"
  echo "binary sha256: $A"; echo "second build sha256: $B"; echo "bytes: $(stat -c %s "$OUT/entropa-gate")"
  [ "$A" = "$B" ] && echo "RESULT: the two builds are byte-identical" || echo "RESULT: DIFFERENT"
} | tee "$OUT/freeze-build-report.txt"
[ "$A" = "$B" ]
