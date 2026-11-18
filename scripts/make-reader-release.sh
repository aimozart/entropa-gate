#!/usr/bin/env bash
# Builds a REHEARSAL release directory with the five published files named in a stage record (not published), signed with THROWAWAY keys made here (never real keys, never in the repo).
# Usage: scripts/make-reader-release.sh PROGRAM BUNDLE_DIR OUT_DIR KEYS_DIR     (OUT_DIR and KEYS_DIR must not exist; needs entropa-release on PATH or RELEASE_TOOL, and minisign)
# Writes OUT_DIR/{entropa-mockview-linux-x86_64, entropa-mockview-linux-x86_64.minisig, SBOM.cdx.json, ledger.tar, MANIFEST.json} and KEYS_DIR/reader-inputs.txt (the PUBLIC values a reader is given).
set -euo pipefail
[ $# -eq 4 ] || { echo "usage: make-reader-release.sh PROGRAM BUNDLE_DIR OUT_DIR KEYS_DIR" >&2; exit 2; }
prog="$1"; bundle="$2"; out="$3"; keys="$4"; tool="${RELEASE_TOOL:-entropa-release}"
[ -e "$out" ] && { echo "refused: OUT_DIR exists" >&2; exit 1; }; [ -e "$keys" ] && { echo "refused: KEYS_DIR exists" >&2; exit 1; }
[ -f "$prog" ] && [ -f "$bundle/ledger.tar" ] && [ -f "$bundle/data/meta.json" ] || { echo "refused: program, bundle/ledger.tar or bundle/data/meta.json missing" >&2; exit 1; }
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out" "$keys"; chmod 700 "$keys"
name=entropa-mockview-linux-x86_64
cp "$prog" "$out/$name"; chmod 755 "$out/$name"; cp "$bundle/ledger.tar" "$out/ledger.tar"
"$tool" sbom --lock "$root/Cargo.lock" --product entropa-mockview --version 0.0.0-rehearsal --out "$out/SBOM.cdx.json" >/dev/null
minisign -G -W -f -p "$keys/entropa.pub" -s "$keys/entropa.key" >/dev/null
minisign -S -s "$keys/entropa.key" -m "$out/$name" >/dev/null
rk=$("$tool" keygen --out "$keys/release.key" | sed -n 's/^public key: //p')
"$tool" sign --dir "$out" --product entropa-mockview --version 0.0.0-rehearsal --sbom "$out/SBOM.cdx.json" --key "$keys/release.key" --out "$out/MANIFEST.json" >/dev/null
lk=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['pubkey'])" "$bundle/data/meta.json")
printf 'RELEASE_PUBKEY_HEX=%s\nMINISIGN_PUB=%s\nLEDGER_PUBKEY_HEX=%s\n' "$rk" "$keys/entropa.pub" "$lk" > "$keys/reader-inputs.txt"
echo "release directory: $out ($(ls "$out" | wc -l) files); public inputs: $keys/reader-inputs.txt"
