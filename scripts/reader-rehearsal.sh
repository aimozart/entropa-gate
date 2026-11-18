#!/usr/bin/env bash
# READER REHEARSAL: follow docs/public/VERIFYING.md from a clean directory, using only the published files and the three public values, then try every tamper; each must be REFUSED.
# Usage: scripts/reader-rehearsal.sh RELEASE_DIR RELEASE_PUBKEY_HEX MINISIGN_PUB LEDGER_PUBKEY_HEX WORK_DIR [--bite]
# WORK_DIR must not exist (scratch is left in place, nothing is deleted). entropa-release (RELEASE_TOOL) and minisign must be installed.
# --bite replaces the verify program by one that accepts everything (/bin/true) and skips the program check: the tamper cases must then FAIL, which shows the rehearsal can see a bad verifier.
set -uo pipefail
[ $# -ge 5 ] || { echo "usage: reader-rehearsal.sh RELEASE_DIR RELEASE_PUBKEY_HEX MINISIGN_PUB LEDGER_PUBKEY_HEX WORK_DIR [--bite]" >&2; exit 2; }
rel="$1"; rk="$2"; mpub="$3"; lk="$4"; work="$5"; bite="${6:-}"; tool="${RELEASE_TOOL:-entropa-release}"
[ -e "$work" ] && { echo "refused: WORK_DIR exists" >&2; exit 1; }
name=entropa-mockview-linux-x86_64
mkdir -p "$work"; pass=0; fail=0
# expect NAME WANT(ok|refuse) -- COMMAND...   (runs the command; ok = exit 0, refuse = exit EXACTLY 1 (the refusal code of every tool used) AND a message: a missing program or a usage error (127, 2) is not a refusal)
expect() { local n="$1" want="$2"; shift 3; local out err rc; out=$("$@" 2>"$work/.err"); rc=$?; err=$(head -c 160 "$work/.err" | head -1)
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = refuse ] && [ $rc -eq 1 ] && [ -n "$err$out" ]; }; then pass=$((pass+1)); echo "PASS $n (want $want; exit $rc; ${out:0:60}${err:0:90})"
  else fail=$((fail+1)); echo "FAIL $n (want $want; exit $rc; ${out:0:60}${err:0:90})"; fi; }
prog="$work/reader/$name"; mkdir -p "$work/reader" "$work/led"
cp "$rel"/* "$work/reader/"; chmod 755 "$prog"
[ "$bite" = --bite ] && prog=/bin/true
echo "== step 1: check the program against the manifest and the minisign signature"
if [ "$bite" != --bite ]; then
  expect s1-manifest ok -- "$tool" verify --dir "$work/reader" --manifest "$work/reader/MANIFEST.json" --pubkey "$rk"
  expect s1-minisign ok -- minisign -Vm "$work/reader/$name" -p "$mpub"
fi
echo "== step 2: unpack the ledger (exactly the three files)"
tar -xf "$work/reader/ledger.tar" -C "$work/led"; ls -R "$work/led" | grep -v '^$' | tr '\n' ' '; echo
echo "== step 3: verify"
[ "$bite" = --bite ] && vcmd=("$prog") || vcmd=("$prog" verify)
expect s3-verify-good ok -- "${vcmd[@]}" "$work/led" "$lk"
echo "== tampers (each on a fresh copy; each must be refused)"
copy() { mkdir -p "$work/$1"; cp -r "$work/led/." "$work/$1/"; }
flip() { python3 - "$1" "$2" <<'PY'
import sys
p=sys.argv[1]; at=int(sys.argv[2]); b=bytearray(open(p,'rb').read()); b[at]=ord('1') if b[at]==ord('0') else ord('0'); open(p,'wb').write(b)
PY
}
copy t1; flip "$work/t1/evidence-ledger/records.log" 100; expect t1-flipped-byte refuse -- "${vcmd[@]}" "$work/t1" "$lk"
expect t2-wrong-key refuse -- "${vcmd[@]}" "$work/led" "$(printf '%0*d' ${#lk} 0)"
copy t3; python3 - "$work/t3/evidence-ledger/records.log" <<'PY'
import sys
p=sys.argv[1]; b=open(p,'rb').read(); open(p,'wb').write(b[:-50])
PY
expect t3-truncated-records refuse -- "${vcmd[@]}" "$work/t3" "$lk"
copy t4; python3 - "$work/t4/evidence-ledger/checkpoints.log" <<'PY'
import sys
p=sys.argv[1]; lines=open(p).read().splitlines(True); open(p,'w').write(''.join(lines[:-1]))
PY
expect t4-last-checkpoint-missing refuse -- "${vcmd[@]}" "$work/t4" "$lk"
mkdir -p "$work/t5"; expect t5-no-ledger-directory refuse -- "${vcmd[@]}" "$work/t5" "$lk"
copy t6; chmod -R a-w "$work/t6"; expect t6-read-only-good ok -- "${vcmd[@]}" "$work/t6" "$lk"
copy t7; flip "$work/t7/evidence-ledger/checkpoints.log" 120; chmod -R a-w "$work/t7"; expect t7-read-only-tampered refuse -- "${vcmd[@]}" "$work/t7" "$lk"
if [ "$bite" != --bite ]; then
  mkdir -p "$work/t8"; cp "$work/reader/"* "$work/t8/"; flip "$work/t8/$name" 4000
  expect t8-tampered-program-manifest refuse -- "$tool" verify --dir "$work/t8" --manifest "$work/t8/MANIFEST.json" --pubkey "$rk"
  expect t8-tampered-program-minisign refuse -- minisign -Vm "$work/t8/$name" -p "$mpub"
  mkdir -p "$work/t9"; cp "$work/reader/"* "$work/t9/"; flip "$work/t9/ledger.tar" 1200
  expect t9-tampered-tar-manifest refuse -- "$tool" verify --dir "$work/t9" --manifest "$work/t9/MANIFEST.json" --pubkey "$rk"
  mkdir -p "$work/t10"; cp "$work/reader/"* "$work/t10/"; echo extra > "$work/t10/extra.txt"
  expect t10-extra-file refuse -- "$tool" verify --dir "$work/t10" --manifest "$work/t10/MANIFEST.json" --pubkey "$rk"
  mkdir -p "$work/t11"; for f in "$work/reader/"*; do [ "$(basename "$f")" = SBOM.cdx.json ] || cp "$f" "$work/t11/"; done
  expect t11-missing-sbom refuse -- "$tool" verify --dir "$work/t11" --manifest "$work/t11/MANIFEST.json" --pubkey "$rk"
  expect t12-wrong-release-key refuse -- "$tool" verify --dir "$work/reader" --manifest "$work/reader/MANIFEST.json" --pubkey "$(printf '%0*d' ${#rk} 0)"
  if command -v docker >/dev/null 2>&1 && docker image inspect entropa-dev:1 >/dev/null 2>&1; then
    dk() { docker run --rm --network none --read-only --memory=512m -v "$prog":/usr/local/bin/v:ro -v "$1":/led:ro entropa-dev:1 v verify /led "$lk"; }
    expect t13-container-read-only-good ok -- dk "$work/led"
    expect t13-container-read-only-tampered refuse -- dk "$work/t1"
  fi
fi
echo "RESULT: $pass passed, $fail failed (work dir $work, kept)"
[ $fail -eq 0 ]
