#!/usr/bin/env bash
# PKG1: build the Linux package of entropa-gate (a stage record (not published)). Usage: scripts/pkg1-build.sh OUT_DIR
# Builds entropa-gate and entropa-release (static glibc) TWICE in different target directories, assembles the tarball TWICE from the two sets, signs (SHA256SUMS with
# minisign, the manifest with ML-DSA-65), compares everything and builds the FROM-scratch image. TEST KEYS are generated in OUT_DIR/testkeys unless PKG1_KEY_DIR
# names a key directory laid out as in docs/RELEASE-KEY-STEPS.md (the owner's offline stick, or a throwaway one for a rehearsal).
# Limits: 6 GB cap, nothing pulled, nothing deleted (old builds stay), no network use by any step.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="$PWD"
source "$SRC/scripts/lib-pkg1.sh"
OUT="${1:?usage: pkg1-build.sh OUT_DIR}"
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9); [ "$free_gb" -ge 25 ] || { echo "refusing to start: only ${free_gb} GB free on / (rule: at least 25 GB)" >&2; exit 1; }
mkdir -p "$OUT"
export CARGO_NET_OFFLINE=true SOURCE_DATE_EPOCH=1700000000
TARGET=x86_64-unknown-linux-gnu
VERSION=$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version = "\(.*\)"/\1/p}' Cargo.toml | head -1)
[ -n "$VERSION" ] || { echo "no workspace version" >&2; exit 1; }
stamp=$(date +%Y%m%dT%H%M%S)

build() { # $1 = a target directory; $2 = directory for the two binaries
  mkdir -p "$2"
  RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--build-id=none --remap-path-prefix=$SRC=/src --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup" \
  CARGO_PROFILE_RELEASE_STRIP=symbols CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_TARGET_DIR="$1" \
  timeout 3000 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 \
    cargo build --release --locked --offline -j2 -p entropa-gate -p entropa-release --target "$TARGET" >&2
  cp "$1/$TARGET/release/entropa-gate" "$1/$TARGET/release/entropa-release" "$2/"
}
echo "== build 1" >&2; build "$OUT/target-$stamp-1" "$OUT/bin1"
echo "== build 2 (a different target directory)" >&2; build "$OUT/target-$stamp-2" "$OUT/bin2"
same=yes
for b in entropa-gate entropa-release; do cmp -s "$OUT/bin1/$b" "$OUT/bin2/$b" || same=no; done

# keys: test keys unless a REAL key directory is named (PKG1_KEY_DIR holding entropa-release-minisign.key/.pub, entropa-release-mldsa.seed and
# public-key-and-id.txt, as in docs/RELEASE-KEY-STEPS.md). The seed and the secret key are only READ, never copied into the package or the repository.
PUB="$OUT/pubkeys"; mkdir -p "$PUB"
if [ -n "${PKG1_KEY_DIR:-}" ]; then
  KD="$PKG1_KEY_DIR"; MLK="$KD/entropa-release-mldsa.seed"; MSK="$KD/entropa-release-minisign.key"
  for f in "$MLK" "$MSK" "$KD/entropa-release-minisign.pub" "$KD/public-key-and-id.txt"; do [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }; done
  sed -n 's/^public key: //p' "$KD/public-key-and-id.txt" | head -1 > "$PUB/mldsa.pub.hex"; sed -n '2p' "$KD/entropa-release-minisign.pub" > "$PUB/minisign.pub.line"
  keykind="keys from the directory named by PKG1_KEY_DIR (the owner's key directory or a rehearsal directory; see the report's key line for which)"
else
  KD="$OUT/testkeys"; mkdir -p "$KD"; MLK="$KD/mldsa.seed"; MSK="$KD/minisign.key"
  if [ ! -f "$MLK" ]; then "$OUT/bin1/entropa-release" keygen --out "$MLK" | sed -n 's/^public key: //p' > "$KD/mldsa.pub.hex"; fi
  if [ ! -f "$MSK" ]; then minisign -G -W -f -p "$KD/minisign.pub" -s "$MSK" >/dev/null; sed -n '2p' "$KD/minisign.pub" > "$KD/minisign.pub.line"; fi
  cp "$KD/mldsa.pub.hex" "$PUB/mldsa.pub.hex"; cp "$KD/minisign.pub.line" "$PUB/minisign.pub.line"
  keykind="TEST keys generated at run time in $KD (never a real release key)"
fi

assemble() { # $1 = binaries directory, $2 = work directory (new), $3 = tarball path
  local stage="$2/entropa-gate-$VERSION"
  mkdir -p "$stage"
  cp "$1/entropa-gate" "$1/entropa-release" "$stage/"
  cp packaging/pkg1/install.sh packaging/pkg1/uninstall.sh packaging/pkg1/README.txt "$stage/"
  cp "$(pkg1_license_file "$SRC")" "$stage/LICENSE"
  printf '%s\n' "$VERSION" > "$stage/VERSION"
  chmod 0755 "$stage/entropa-gate" "$stage/entropa-release" "$stage/install.sh" "$stage/uninstall.sh"; chmod 0644 "$stage/README.txt" "$stage/LICENSE" "$stage/VERSION"
  "$stage/entropa-release" sbom --lock Cargo.lock --product entropa-gate --version "$VERSION" --out "$stage/SBOM.cdx.json" >/dev/null
  chmod 0644 "$stage/SBOM.cdx.json"
  (cd "$stage" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum > ../SHA256SUMS.tmp && mv ../SHA256SUMS.tmp SHA256SUMS)
  minisign -S -s "$MSK" -t "entropa-gate $VERSION" -x "$stage/SHA256SUMS.minisig" -m "$stage/SHA256SUMS" >/dev/null
  chmod 0644 "$stage/SHA256SUMS" "$stage/SHA256SUMS.minisig"
  "$stage/entropa-release" sign --dir "$stage" --product entropa-gate --version "$VERSION" --sbom "$stage/SBOM.cdx.json" --key "$MLK" --out "$stage/MANIFEST.json" >/dev/null
  chmod 0644 "$stage/MANIFEST.json"
  (cd "$2" && tar --sort=name --mtime=@"$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner --format=gnu -cf - "entropa-gate-$VERSION" | gzip -n -9 > "$3")
}
T1="$OUT/entropa-gate-$VERSION-linux-x86_64.tar.gz"
[ ! -e "$T1" ] || { echo "refusing to overwrite $T1 (use a new OUT_DIR)" >&2; exit 1; }
assemble "$OUT/bin1" "$OUT/asm1-$stamp" "$T1"
assemble "$OUT/bin2" "$OUT/asm2-$stamp" "$OUT/second-$VERSION.tar.gz"
A=$(sha256sum "$T1" | cut -d' ' -f1); B=$(sha256sum "$OUT/second-$VERSION.tar.gz" | cut -d' ' -f1)

# the image (FROM scratch) from the first binary
CTX="$OUT/ctx"; mkdir -p "$CTX/data"
cp packaging/Dockerfile "$CTX/Dockerfile"; cp packaging/data/.keep "$CTX/data/.keep"; cp "$OUT/bin1/entropa-gate" "$CTX/entropa-gate"; chmod 0555 "$CTX/entropa-gate"
TAG="entropa-gate:pkg1-${A:0:12}"
docker build -q -t "$TAG" "$CTX" >/dev/null
SIZE=$(docker image inspect --format '{{.Size}}' "$TAG")

{
  echo "PKG1 package report ($stamp)"
  echo "version: $VERSION"
  echo "tarball sha256: $A"
  echo "second tarball sha256: $B"
  echo "tarball bytes: $(stat -c %s "$T1")"
  if [ "$A" = "$B" ]; then echo "tarball reproducible: yes (two builds, two assemblies, same bytes)"; else echo "tarball reproducible: NO ($(cmp -l "$T1" "$OUT/second-$VERSION.tar.gz" | wc -l) bytes differ)"; fi
  echo "binaries identical: $same"
  echo "entropa-gate sha256: $(sha256sum "$OUT/bin1/entropa-gate" | cut -d' ' -f1)"
  echo "entropa-release sha256: $(sha256sum "$OUT/bin1/entropa-release" | cut -d' ' -f1)"
  echo "link: $(file -b "$OUT/bin1/entropa-gate")"
  echo "toolchain: $(rustc --version)"
  echo "keys: $keykind"
  echo "image tag: $TAG"
  echo "image bytes: $SIZE"
  echo "scope: built and tested on this machine only (linux x86_64, glibc static); the two builds share host, kernel, toolchain and crate cache; no independent review; nothing published"
} > "$OUT/report.txt"
cat "$OUT/report.txt"
