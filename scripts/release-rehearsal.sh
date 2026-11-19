#!/usr/bin/env bash
# Release rehearsal (S2 finish): the whole release chain end to end, in ONE command. With no --key-dir it uses throwaway TEST keys (a rehearsal);
# with --key-dir DIR it signs a REAL release with the key directory laid out as in docs/RELEASE-KEY-STEPS.md (the owner's offline key stick). Same code path both ways.
#   scripts/release-rehearsal.sh [--key-dir DIR] [--out DIR]
# Steps: 1 build twice and sign (pkg1-build.sh) -> 2 the install test suite on the result (pkg1-install.sh) -> 3 verify from a CLEAN CHECKOUT with a verifier built from
# source (not the one in the tarball) under the public keys -> 4 tamper test -> 5 print what to publish. Nothing is published, nothing is deleted.
# A real minisign key with a password is asked for its password by minisign (twice: the package is assembled twice for the reproducibility check).
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="$PWD"
KEYDIR=""; OUT=""
while [ $# -gt 0 ]; do case "$1" in --key-dir) KEYDIR=$2; shift 2 ;; --out) OUT=$2; shift 2 ;; *) echo "usage: release-rehearsal.sh [--key-dir DIR] [--out DIR]" >&2; exit 2 ;; esac; done
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9); [ "$free_gb" -ge 25 ] || { echo "refusing to start: only ${free_gb} GB free on / (rule: at least 25 GB)" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "refusing: the working tree has uncommitted changes (a release is built from a commit)" >&2; exit 1; }
OUT="${OUT:-$HOME/.cache/build/release-rehearsal-$(date +%Y%m%dT%H%M%S)}"
[ ! -e "$OUT" ] || { echo "refusing: $OUT exists" >&2; exit 1; }
[ -z "$KEYDIR" ] && echo "REHEARSAL with throwaway test keys (nothing real is signed)" || echo "REAL RELEASE: signing with the keys in $KEYDIR"
step() { echo; echo "== $*"; }
step "1. build twice, assemble twice, sign"
if [ -n "$KEYDIR" ]; then PKG1_KEY_DIR="$KEYDIR" scripts/pkg1-build.sh "$OUT/pkg" > "$OUT.build.log" 2>&1 || { echo "build failed, see $OUT.build.log" >&2; exit 1; }
else scripts/pkg1-build.sh "$OUT/pkg" > "$OUT.build.log" 2>&1 || { echo "build failed, see $OUT.build.log" >&2; exit 1; }; fi
grep -E "^(tarball sha256|second tarball sha256|tarball reproducible|binaries identical|keys)" "$OUT/pkg/report.txt"
grep -q "^tarball reproducible: yes" "$OUT/pkg/report.txt" || { echo "STOP: the two tarballs differ" >&2; exit 1; }
TAR=$(ls "$OUT"/pkg/entropa-gate-*-linux-x86_64.tar.gz | head -1)
MS_PUB=$(cat "$OUT/pkg/pubkeys/minisign.pub.line"); DL_PUB=$(cat "$OUT/pkg/pubkeys/mldsa.pub.hex")
step "2. the install test suite on the built package (empty homes, 9 refusal classes, root refusal, Debian container with no network)"
PKG1_REUSE=1 PKG1_OUT="$OUT/pkg" scripts/tests/pkg1-install.sh > "$OUT/install-test.txt" 2>&1 || { tail -5 "$OUT/install-test.txt"; echo "STOP: the install tests failed" >&2; exit 1; }
tail -1 "$OUT/install-test.txt"; echo "$(grep -c '^ok' "$OUT/install-test.txt") checks ok"
step "3. verify from a CLEAN CHECKOUT with a verifier built from source"
C="/tmp/tmp-rehearsal/clean-$(date +%Y%m%dT%H%M%S)"; mkdir -p /tmp/tmp-rehearsal
git clone -q --no-hardlinks "$SRC" "$C"; head=$(git -C "$C" rev-parse --short HEAD)
(cd "$C" && CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$C/target" timeout 1500 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 cargo build --release --locked --offline -j2 -p entropa-release >/dev/null 2>&1) || { echo "STOP: the clean checkout did not build" >&2; exit 1; }
V="$C/target/release/entropa-release"; X="/tmp/tmp-rehearsal/extract-$(date +%Y%m%dT%H%M%S)"; mkdir -p "$X"; tar -xzf "$TAR" -C "$X"; P=$(ls -d "$X"/entropa-gate-*/)
"$V" verify --dir "$P" --manifest "$P/MANIFEST.json" --pubkey "$DL_PUB" > /dev/null && echo "ML-DSA manifest verifies with the verifier built from commit $head (not the one in the tarball)"
(cd "$P" && minisign -V -P "$MS_PUB" -x SHA256SUMS.minisig -m SHA256SUMS >/dev/null && sha256sum -c SHA256SUMS --quiet && echo "minisign signature and every checksum verify")
step "4. tamper test (a copy with one byte changed must NOT verify)"
cp -r "$P" "$X/tampered"; printf 'X' >> "$X/tampered/entropa-gate"
if "$V" verify --dir "$X/tampered" --manifest "$X/tampered/MANIFEST.json" --pubkey "$DL_PUB" >/dev/null 2>&1; then echo "STOP: a tampered copy verified" >&2; exit 1; else echo "tampered copy refused (ML-DSA)"; fi
if (cd "$X/tampered" && sha256sum -c SHA256SUMS --quiet >/dev/null 2>&1); then echo "STOP: a tampered copy passed sha256sum" >&2; exit 1; else echo "tampered copy refused (sha256sum)"; fi
step "5. what to publish (nothing has been published)"
echo "files: $TAR  (and its sha256: $(sha256sum "$TAR" | cut -c1-64))"
echo "public key lines to publish on TWO channels: minisign: $MS_PUB ; ML-DSA key fingerprint (sha256 of the key text, first 16 hex): $(printf '%s' "$DL_PUB" | sha256sum | cut -c1-16)"
echo "done: $OUT (built from commit $head; evidence: $OUT/pkg/report.txt, $OUT/install-test.txt)"
