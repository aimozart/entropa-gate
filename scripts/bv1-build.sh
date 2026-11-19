#!/usr/bin/env bash
# BV1: build the browser verifier (wasm + the single page) and run the checks. Offline, locked; uses the `stable` toolchain (same rustc as the pinned one; the wasm32 target is installed there). Usage: scripts/bv1-build.sh OUT_DIR  (must not exist)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:?usage: bv1-build.sh OUT_DIR}"; [ ! -e "$OUT" ] || { echo "refused: $OUT exists" >&2; exit 2; }
export RUSTUP_TOOLCHAIN=stable CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/build/bv1-target}" TMPDIR="${TMPDIR:-/tmp/tmp-bv1}"
mkdir -p "$OUT" "$TMPDIR"
scripts/tests/wasm-verify-build.sh entropa-core entropa-witness entropa-approvals entropa-policy entropa-ledger entropa-bundle-verify
cargo build --profile wasm --offline --locked --target wasm32-unknown-unknown -p entropa-bundle-verify
W="$CARGO_TARGET_DIR/wasm32-unknown-unknown/wasm/entropa_bundle_verify.wasm"
cp "$W" "$OUT/entropa_bundle_verify.wasm"; sha256sum "$OUT/entropa_bundle_verify.wasm" | tee "$OUT/wasm.sha256"; stat -c 'wasm bytes: %s' "$W"; gzip -9 -c "$W" | wc -c | sed 's/^/wasm gzip bytes: /'
python3 tools/bv1/make-page.py "$W" "$OUT/checker.html"
CORPUS_EXPORT="$OUT/corpus" cargo test --offline --locked -p entropa-ledger --test bundle_corpus -- --quiet
BV1_CORPUS_DIR="$OUT/corpus" cargo test --offline --locked -p entropa-bundle-verify -- --include-ignored
node tools/bv1/run-corpus.mjs "$W" crates/ledger/tests/bundle_corpus/manifest.json "$OUT/corpus"
mkdir -p "$TMPDIR/chrome"; node tools/bv1/chrome-run.mjs "$OUT/checker.html" crates/ledger/tests/bundle_corpus/manifest.json "$OUT/corpus" "$TMPDIR/chrome"
