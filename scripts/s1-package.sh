#!/usr/bin/env bash
# S1 task 5: build the client binary twice (static glibc, no install needed), compare the two SHA-256 values, and build the minimal image from the first.
# Output directory: $S1_OUT (default ~/.cache/build/s1-package): entropa-gate, report.txt, ctx/ (the image build context).
# Limits: every build runs under a 6 GB memory cap with -j2; nothing is pulled (the image is FROM scratch); nothing is deleted (old builds are left in place).
# Reproducibility is REPORTED, not assumed: if the two hashes differ the report says so and shows where.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="$PWD"
OUT="${S1_OUT:-$HOME/.cache/build/s1-package}"
mkdir -p "$OUT"
export CARGO_NET_OFFLINE=true SOURCE_DATE_EPOCH=1700000000
TARGET=x86_64-unknown-linux-gnu

build() { # $1 = a target directory for this build
  RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--build-id=none --remap-path-prefix=$SRC=/src --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup" \
  CARGO_PROFILE_RELEASE_STRIP=symbols CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_TARGET_DIR="$1" \
  timeout 3000 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 \
    cargo build --release --locked --offline -j2 -p entropa-gate --target "$TARGET"
  cp "$1/$TARGET/release/entropa-gate" "$2"
}

stamp=$(date +%Y%m%dT%H%M%S)
T1="$OUT/target-$stamp-1"; T2="$OUT/target-$stamp-2"
echo "== build 1" >&2; build "$T1" "$OUT/entropa-gate"
echo "== build 2 (a different target directory)" >&2; build "$T2" "$OUT/entropa-gate.second"
A=$(sha256sum "$OUT/entropa-gate" | cut -d' ' -f1); B=$(sha256sum "$OUT/entropa-gate.second" | cut -d' ' -f1)

CTX="$OUT/ctx"; mkdir -p "$CTX/data"
cp packaging/Dockerfile "$CTX/Dockerfile"; cp packaging/data/.keep "$CTX/data/.keep"; cp "$OUT/entropa-gate" "$CTX/entropa-gate"; chmod 0555 "$CTX/entropa-gate"  # the legacy builder has no --chmod: the mode is set here and COPY keeps it
TAG="entropa-gate:s1-${A:0:12}"
echo "== image $TAG (FROM scratch, nothing pulled)" >&2
docker build -q -t "$TAG" "$CTX" >/dev/null
ID=$(docker image inspect --format '{{.Id}}' "$TAG")
SIZE=$(docker image inspect --format '{{.Size}}' "$TAG")

{
  echo "S1 packaging report ($stamp)"
  echo "binary sha256: $A"
  echo "second build sha256: $B"
  echo "binary bytes: $(stat -c %s "$OUT/entropa-gate")"
  if [ "$A" = "$B" ]; then
    echo "reproducible: yes (two builds in different target directories gave the same SHA-256; same source path and toolchain)"
  else
    echo "reproducible: no (the two builds differ)"
    echo "difference: $(cmp -l "$OUT/entropa-gate" "$OUT/entropa-gate.second" | wc -l) bytes differ; sizes $(stat -c %s "$OUT/entropa-gate") and $(stat -c %s "$OUT/entropa-gate.second"); first difference at byte $(cmp "$OUT/entropa-gate" "$OUT/entropa-gate.second" | sed -n 's/.*byte \([0-9]*\).*/\1/p')"
  fi
  echo "link: $(file -b "$OUT/entropa-gate")"
  echo "toolchain: $(rustc --version)"
  echo "image tag: $TAG"
  echo "image id: $ID"
  echo "image bytes: $SIZE"
  echo "scope: built and tested on this machine only (linux x86_64, glibc static); no image signature, no SBOM (S2); a static glibc binary can differ from a musl one"
} > "$OUT/report.txt"
cat "$OUT/report.txt"
