#!/usr/bin/env bash
# PKG1 tests (a stage record (not published), P1-P9), run on the package that scripts/pkg1-build.sh builds. PKG1_REUSE=1 reuses the last build.
# The release keys here are TEST keys generated at run time by the build script (never a real key); the trust anchors are passed to install.sh as arguments.
set -u
cd "$(dirname "$0")/../.."
OUT="${PKG1_OUT:-$HOME/.cache/build/pkg1-package}"
WORK="${PKG1_WORK:-/tmp/tmp-pkg1/test-$(date +%Y%m%dT%H%M%S)}"   # one per-stage scratch directory on tmpfs (volatile); every test directory is a NEW one; this script removes nothing
fail=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
mkdir -p "$WORK"

[ -x scripts/pkg1-build.sh ] || { bad "scripts/pkg1-build.sh is missing or not executable"; exit 1; }
if [ "${PKG1_REUSE:-0}" != 1 ]; then
  mkdir -p "$OUT"
  timeout 5400 scripts/pkg1-build.sh "$OUT" > "$OUT.build.log" 2>&1 || bad "scripts/pkg1-build.sh failed (see $OUT.build.log)"
fi
REPORT="$OUT/report.txt"
TAR=$(ls "$OUT"/entropa-gate-*-linux-x86_64.tar.gz 2>/dev/null | head -1)
[ -n "$TAR" ] && ok "tarball exists: $(basename "$TAR")" || { bad "no tarball in $OUT"; exit 1; }
[ -f "$REPORT" ] && ok "report exists" || { bad "no report"; exit 1; }
MS_PUB=$(cat "$OUT/pubkeys/minisign.pub.line" 2>/dev/null); DL_PUB=$(cat "$OUT/pubkeys/mldsa.pub.hex" 2>/dev/null)
[ -n "$MS_PUB" ] && [ -n "$DL_PUB" ] && ok "trust anchors (public keys) present" || { bad "no public keys in $OUT/pubkeys"; exit 1; }

# P1 reproducibility
A=$(sha256sum "$TAR" | cut -d' ' -f1)
grep -q "^tarball sha256: $A" "$REPORT" && ok "report sha256 matches the tarball" || bad "report sha256 does not match"
grep -q "^second tarball sha256: $A" "$REPORT" && ok "P1 the second build gave the same tarball" || bad "P1 the second tarball differs or is missing in the report"
grep -q "^binaries identical: yes" "$REPORT" && ok "P1 the two binaries are identical" || bad "P1 binaries not identical"
tar -tzf "$TAR" | head -1 | grep -q '^entropa-gate-[^/]*/$' && ok "one top directory" || bad "no single top directory"
for f in entropa-gate entropa-release install.sh uninstall.sh LICENSE README.txt VERSION SBOM.cdx.json SHA256SUMS SHA256SUMS.minisig MANIFEST.json; do
  tar -tzf "$TAR" | grep -q "/$f\$" && ok "contains $f" || bad "missing $f"
done
tar -tvzf "$TAR" --numeric-owner | awk '{print $2}' | sort -u | grep -qv '^0/0$' && bad "an entry has an owner other than 0/0" || ok "all entries owned by 0/0"

extract() { # $1 = new dir name; prints the package directory
  d="$WORK/$1"; mkdir -p "$d"; tar -xzf "$TAR" -C "$d"; ls -d "$d"/entropa-gate-*/
}
tree() { find "$1" -mindepth 1 2>/dev/null | sort; }

# P2 install (minisign mode) into an empty HOME, then the app works
H="$WORK/home-a"; mkdir -p "$H"; PK=$(extract pkg-a)
out=$(cd "$PK" && HOME="$H" sh ./install.sh --minisign-pubkey "$MS_PUB" 2>&1); rc=$?
[ $rc -eq 0 ] && ok "P2 install (minisign mode) exit 0" || { bad "P2 install failed: $out"; }
VER=$(sed -n 's/^version: //p' "$REPORT")
echo "$out" | grep -q "installed entropa-gate $VER into" && ok "P2 the installer names the real version ($VER), not 'unknown'" || bad "P2 the installer does not name the version $VER"
echo "$out" | grep -q "uninstall: sh $H/.local/share/entropa-gate/uninstall.sh" && ok "P2 the installer's last lines say how to uninstall (the installed copy)" || bad "P2 no uninstall instruction in the installer output"
echo "$out" | grep -qi "verification mode: minisign" && ok "P2 prints the verification mode" || bad "P2 does not print the verification mode"
echo "$out" | grep -qi "not checked" && ok "P2 prints what it did not check" || bad "P2 does not print what it did not check"
[ -x "$H/.local/bin/entropa-gate" ] && ok "P2 binary installed in ~/.local/bin" || bad "P2 binary not installed"
G="$H/.local/bin/entropa-gate"; N="$WORK/node-a"
REQ='{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"How many claims were denied by payer?","output":"SELECT 1","run_id":"run-pkg1","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":1,"cost_micro_usd":1}'
"$G" status --dir "$N" >/dev/null 2>&1; true
HOME="$H" "$G" init --dir "$N" >/dev/null 2>&1 && ok "P2 init works" || bad "P2 init failed"
printf '%s' "$REQ" | HOME="$H" "$G" record --dir "$N" >/dev/null 2>&1 && ok "P2 record works" || bad "P2 record failed"
HOME="$H" "$G" verify --dir "$N" 2>&1 | grep -q "OK" && ok "P2 verify works" || bad "P2 verify failed"
find "$H" -name '*.key' | grep -q . && bad "P2 the installer created a key file" || ok "P2 the installer created no key"
[ -f "$H/.local/share/entropa-gate/install-record" ] && ok "P2 an install record exists" || bad "P2 no install record"
# writes only under the prefix
tree "$H" | grep -vE "^$H/\.local(/|$)" | grep -q . && bad "P2 something was written outside the prefix" || ok "P2 nothing written outside the prefix"

# P2b the ML-DSA mode (bundled verifier): works and says it is the weaker mode
H2="$WORK/home-b"; mkdir -p "$H2"; PK2=$(extract pkg-b)
out=$(cd "$PK2" && HOME="$H2" sh ./install.sh --pubkey "$DL_PUB" 2>&1); rc=$?
[ $rc -eq 0 ] && ok "P2b install (ML-DSA mode) exit 0" || bad "P2b install failed: $out"
echo "$out" | grep -qi "verification mode: ml-dsa" && ok "P2b prints the mode" || bad "P2b no mode line"
echo "$out" | grep -qi "same tarball" && ok "P2b warns that the verifier came from the same tarball" || bad "P2b no warning about the bundled verifier"

# P3 refusals, in both modes: nothing is installed
refuse() { # $1 name, $2 mode args, $3 package dir
  hh="$WORK/home-r-$1"; mkdir -p "$hh"
  o=$(cd "$3" && HOME="$hh" sh ./install.sh $2 2>&1); r=$?
  if [ $r -ne 0 ] && [ -z "$(tree "$hh")" ]; then ok "P3 refused with nothing installed: $1"; else bad "P3 $1 (exit $r, leftovers: $(tree "$hh" | head -3 | tr '\n' ' '))"; fi
}
for mode in ms ml; do
  if [ $mode = ms ]; then ARGS="--minisign-pubkey $MS_PUB"; else ARGS="--pubkey $DL_PUB"; fi
  refuse "$mode no trust anchor" "" "$(extract t-$mode-none)"
  refuse "$mode wrong key" "$( [ $mode = ms ] && echo "--minisign-pubkey RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3" || echo "--pubkey $(printf '%064d' 7)" )" "$(extract t-$mode-wk)"
  p=$(extract t-$mode-bin); printf 'X' >> "$p/entropa-gate"; refuse "$mode changed binary" "$ARGS" "$p"
  p=$(extract t-$mode-inst); printf '# x\n' >> "$p/install.sh"; refuse "$mode changed install.sh" "$ARGS" "$p"
  p=$(extract t-$mode-sbom); printf ' ' >> "$p/SBOM.cdx.json"; refuse "$mode changed SBOM" "$ARGS" "$p"
  p=$(extract t-$mode-miss); mv "$p/README.txt" "$p/README.moved"; refuse "$mode missing file" "$ARGS" "$p"
  p=$(extract t-$mode-extra); echo extra > "$p/extra.txt"; refuse "$mode extra file" "$ARGS" "$p"
  if [ $mode = ml ]; then
    # a real change of the signed content (a space after the last byte is not a change of content)
    p=$(extract t-$mode-man); sed -i '0,/[0-9a-f]\{64\}/s//0000000000000000000000000000000000000000000000000000000000000000/' "$p/MANIFEST.json"; refuse "$mode changed manifest" "$ARGS" "$p"
  else
    echo "n/a  P3 minisign mode does not read MANIFEST.json (SHA256SUMS covers every other file); the ML-DSA mode does"
  fi
done
# a truncated tarball does not even extract cleanly
head -c 1000 "$TAR" > "$WORK/trunc.tar.gz"; mkdir -p "$WORK/trunc"; tar -xzf "$WORK/trunc.tar.gz" -C "$WORK/trunc" 2>/dev/null && [ -x "$(ls -d "$WORK"/trunc/entropa-gate-*/install.sh 2>/dev/null | head -1)" ] && bad "P3 a truncated tarball yielded an installer" || ok "P3 a truncated tarball yields no installer"

# root refusal (the id command is stubbed to report uid 0), and the flag that allows it
mkdir -p "$WORK/stub"; printf '#!/bin/sh\necho 0\n' > "$WORK/stub/id"; chmod +x "$WORK/stub/id"
H3="$WORK/home-root"; mkdir -p "$H3"; PK3=$(extract pkg-root)
o=$(cd "$PK3" && PATH="$WORK/stub:$PATH" HOME="$H3" sh ./install.sh --minisign-pubkey "$MS_PUB" 2>&1); r=$?
[ $r -ne 0 ] && echo "$o" | grep -qi "root" && [ -z "$(tree "$H3")" ] && ok "root is refused without the flag" || bad "root not refused (exit $r)"
o=$(cd "$PK3" && PATH="$WORK/stub:$PATH" HOME="$H3" sh ./install.sh --allow-root --minisign-pubkey "$MS_PUB" 2>&1); r=$?
[ $r -eq 0 ] && ok "root allowed with --allow-root" || bad "--allow-root did not allow ($o)"

# P4 idempotent re-install, then uninstall removes only what was installed
o=$(cd "$PK" && HOME="$H" sh ./install.sh --minisign-pubkey "$MS_PUB" 2>&1) && ok "P4 second install exit 0" || bad "P4 second install failed"
mkdir -p "$H/.local/bin" ; echo mine > "$H/.local/bin/other-tool"
o=$(HOME="$H" sh "$H/.local/share/entropa-gate/uninstall.sh" 2>&1); r=$?
[ $r -eq 0 ] && ok "P4 uninstall exit 0" || bad "P4 uninstall failed: $o"
[ ! -e "$H/.local/bin/entropa-gate" ] && [ ! -e "$H/.local/bin/entropa-release" ] && [ ! -e "$H/.local/share/entropa-gate/install-record" ] && ok "P4 installed files removed" || bad "P4 installed files remain"
[ -f "$H/.local/bin/other-tool" ] && ok "P4 a foreign file in the same directory is untouched" || bad "P4 uninstall removed a foreign file"
[ -f "$N/platinum.key" ] && [ -d "$N/ledger" ] && ok "P4 the user's node (keys and ledger) is untouched" || bad "P4 uninstall touched the node directory"

# P5 no network, a second distribution, a non-root user and an empty HOME: Debian bookworm container (the Rust build image already on this machine; nothing is pulled)
IMG=rust:1.99.1-bookworm
if docker image inspect "$IMG" >/dev/null 2>&1; then
  PK5=$(extract pkg-net); mkdir -p "$WORK/home-net"; chmod 777 "$WORK/home-net"
  o=$(timeout 120 docker run --rm --network none --user 10001:10001 -e HOME=/home/t -v "$PK5:/pkg:ro" -v "$WORK/home-net:/home/t" "$IMG" sh -c "sh /pkg/install.sh --pubkey $DL_PUB && /home/t/.local/bin/entropa-gate init --dir /home/t/node && /home/t/.local/bin/entropa-gate verify --dir /home/t/node" 2>&1); r=$?
  [ $r -eq 0 ] && ok "P5 Debian bookworm container, no network, non-root, empty HOME: install (ML-DSA mode), init, verify work" || bad "P5 container install failed: $o"
  echo "$o" | grep -q "verification mode: ML-DSA" && ok "P5 the container run used the ML-DSA mode (minisign is not installed there)" || bad "P5 mode line missing in the container run"
else echo "skip P5 (the image $IMG is not present)"; fi

# P6 fresh login shell and an open shell
H6="$WORK/home-login"; mkdir -p "$H6"; PK6=$(extract pkg-login); (cd "$PK6" && HOME="$H6" sh ./install.sh --minisign-pubkey "$MS_PUB" >/dev/null 2>&1)
cp /etc/skel/.profile "$H6/.profile" 2>/dev/null; cp /etc/skel/.bashrc "$H6/.bashrc" 2>/dev/null
env -i HOME="$H6" PATH=/usr/bin:/bin bash -lc 'entropa-gate status --dir /nonexistent-pkg1 >/dev/null 2>&1; command -v entropa-gate' 2>/dev/null | grep -q "$H6/.local/bin/entropa-gate" && ok "P6 a fresh login shell finds it (distro default .profile)" || bad "P6 a fresh login shell does not find it"
env -i HOME="$H6" PATH="$H6/.local/bin:/usr/bin:/bin" bash -c 'hash -r; command -v entropa-gate' | grep -q entropa-gate && ok "P6 an open shell finds it after hash -r when ~/.local/bin is on PATH" || bad "P6 open shell"
(cd "$PK6" && HOME="$H6" PATH=/usr/bin:/bin sh ./install.sh --minisign-pubkey "$MS_PUB" 2>&1) | grep -q 'export PATH=' && ok "P6 off PATH: the installer prints the exact line to add" || bad "P6 no PATH hint"
grep -q "entropa" "$H6/.profile" "$H6/.bashrc" 2>/dev/null && bad "P6 the installer edited a shell file" || ok "P6 no shell file was edited"

# P7 container
if [ -n "$(docker image ls -q "$(sed -n 's/^image tag: //p' "$REPORT")" 2>/dev/null)" ]; then
  TAG=$(sed -n 's/^image tag: //p' "$REPORT"); V="$WORK/vol-c"; mkdir -p "$V"; chmod 777 "$V"
  timeout 60 docker run --rm --network none --read-only --cap-drop ALL -v "$V:/data" "$TAG" init --dir /data/node >/dev/null 2>&1 && ok "P7 container init (no network, read-only, no caps)" || bad "P7 container init"
  printf '%s' "$REQ" | timeout 60 docker run --rm -i --network none --read-only --cap-drop ALL -v "$V:/data" "$TAG" record --dir /data/node >/dev/null 2>&1 && ok "P7 container record" || bad "P7 container record"
  timeout 60 docker run --rm --network none --read-only --cap-drop ALL -v "$V:/data" "$TAG" verify --dir /data/node 2>&1 | grep -q OK && ok "P7 container verify" || bad "P7 container verify"
else bad "P7 the image named in the report is not present"; fi

echo; [ $fail -eq 0 ] && echo "ALL OK" || echo "SOME FAILED"; exit $fail
