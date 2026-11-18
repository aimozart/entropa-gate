#!/usr/bin/env bash
# Build a mock-ledger bundle variant of a chosen size and check it the way a reader would. Nothing is deleted; new directories only.
# Usage: scripts/mock-bundle.sh COUNT [SEED]   Needs release builds of entropa-mockfeed, entropa-mockview, entropa-platinum (cargo build --release).
set -euo pipefail
count="${1:?usage: mock-bundle.sh COUNT [SEED]}"; seed="${2:-20261215}"
root="$(cd "$(dirname "$0")/.." && pwd)"; bin="$root/target/release"; base="${MOCK_OUT:-$HOME/.cache/build}/mock-bundle-$count-$seed-$(date +%s)"
mkdir -p "$base"
"$bin/entropa-mockfeed" --dir "$base/ledger" --seed "$seed" --count "$count" >/dev/null
pk=$("$bin/entropa-platinum" pubkey "$base/ledger")
"$bin/entropa-mockview" "$base/ledger" "$pk" "$base/bundle" --with-ledger
mkdir -p "$base/reader"; tar -xf "$base/bundle/ledger.tar" -C "$base/reader"
if tar -tf "$base/bundle/ledger.tar" | grep -q key; then echo "FAIL: a key-like name is in the tar"; exit 1; fi
"$bin/entropa-mockview" verify "$base/reader" "$pk"
echo "bundle: $base/bundle   tar bytes: $(stat -c %s "$base/bundle/ledger.tar")"
