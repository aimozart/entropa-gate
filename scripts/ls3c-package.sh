#!/usr/bin/env bash
# LS3c: build entropa-try-http TWICE inside a build container with NO network (rust:1.99.1-bookworm, already on this machine; static glibc), compare the two SHA-256 values, and build the minimal image from the first.
# Output directory: $LS3C_OUT (default ~/.cache/build/ls3c-package): entropa-try-http, report.txt, ctx/ (the image build context), ls3c-cargo-home (a COPY of the host registry cache, used read-write by the build container).
# Containers are named and left stopped (the project's no-delete rule). Limits: each build runs with a 6 GB memory cap and -j2; nothing is pulled and nothing is pushed; nothing is deleted (old builds stay in place). Reproducibility is REPORTED, not assumed.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="$PWD"
OUT="${LS3C_OUT:-$HOME/.cache/build/ls3c-package}"
BUILDER="${LS3C_BUILDER:-rust:1.99.1-bookworm}"
mkdir -p "$OUT"
docker image inspect "$BUILDER" >/dev/null 2>&1 || { echo "the build image $BUILDER is not on this machine (nothing is pulled)" >&2; exit 1; }
HOME_CARGO="$OUT/ls3c-cargo-home"
if [ ! -d "$HOME_CARGO/registry" ]; then mkdir -p "$HOME_CARGO"; cp -a "$HOME/.cargo/registry" "$HOME_CARGO/registry"; fi
stamp=$(date +%Y%m%dT%H%M%S)

build() { # $1 = a target directory for this build, $2 = where to put the binary
  mkdir -p "$1"
  timeout 3000 docker run --name "ls3c-build-$stamp-$(basename "$1")" --network none --memory 6g --memory-swap 6g --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e RUSTUP_TOOLCHAIN=1.99.1-x86_64-unknown-linux-gnu -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target -e CARGO_NET_OFFLINE=true -e SOURCE_DATE_EPOCH=1700000000 \
    -e CARGO_PROFILE_RELEASE_STRIP=symbols -e CARGO_PROFILE_RELEASE_DEBUG=0 \
    -e RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--build-id=none --remap-path-prefix=/src=/src --remap-path-prefix=/cargo=/cargo" \
    -v "$SRC":/src:ro -v "$HOME_CARGO":/cargo -v "$1":/target -w /src "$BUILDER" \
    cargo build --release --locked --offline -j2 -p entropa-try-http --target x86_64-unknown-linux-gnu
  cp "$1/x86_64-unknown-linux-gnu/release/entropa-try-http" "$2"
}
echo "== build 1 (container, --network none)" >&2; build "$OUT/target-$stamp-1" "$OUT/entropa-try-http"
echo "== build 2 (a different target directory)" >&2; build "$OUT/target-$stamp-2" "$OUT/entropa-try-http.second"
A=$(sha256sum "$OUT/entropa-try-http" | cut -d' ' -f1); B=$(sha256sum "$OUT/entropa-try-http.second" | cut -d' ' -f1)

CTX="$OUT/ctx"; mkdir -p "$CTX"
cp packaging/try-http/Dockerfile "$CTX/Dockerfile"; cp "$OUT/entropa-try-http" "$CTX/entropa-try-http"; chmod 0555 "$CTX/entropa-try-http"  # the legacy builder has no --chmod: the mode is set here and COPY keeps it
TAG="entropa-try-http:ls3c-${A:0:12}"
echo "== image $TAG (FROM scratch, nothing pulled)" >&2
docker build -q -t "$TAG" "$CTX" >/dev/null
ID=$(docker image inspect --format '{{.Id}}' "$TAG"); SIZE=$(docker image inspect --format '{{.Size}}' "$TAG")
{
  echo "LS3c packaging report ($stamp)"
  echo "binary sha256: $A"
  echo "second build sha256: $B"
  echo "binary bytes: $(stat -c %s "$OUT/entropa-try-http")"
  if [ "$A" = "$B" ]; then echo "reproducible: yes (two builds in different host target directories, the same container, source and cargo cache, gave the same SHA-256)"
  else echo "reproducible: no (the two builds differ: $(cmp -l "$OUT/entropa-try-http" "$OUT/entropa-try-http.second" | wc -l) bytes; sizes $(stat -c %s "$OUT/entropa-try-http") and $(stat -c %s "$OUT/entropa-try-http.second"))"; fi
  echo "build: container $BUILDER (image id $(docker image inspect --format '{{.Id}}' "$BUILDER" | cut -c1-19)) --network none, source mounted read-only, memory 6g"
  echo "link: $(file -b "$OUT/entropa-try-http")"
  echo "base image: scratch (nothing pulled)"
  echo "image tag: $TAG"
  echo "image id: $ID"
  echo "image bytes: $SIZE"
  echo "scope: built and tested on this machine only (linux x86_64, glibc static); no image signature, no SBOM (S2); not pushed; a static glibc binary can differ from a musl one"
} > "$OUT/report.txt"
cat "$OUT/report.txt"
