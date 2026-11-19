#!/usr/bin/env bash
# DOC-INSTALL1: run every command of docs/public-drafts/INSTALL-THE-GATE.md for real in a clean container (no network, a non-root user, an empty home) against the package that scripts/pkg1-build.sh built, and check every claim the guide makes about the outputs.
# Usage: scripts/tests/doc-install1.sh PKG_DIR IMAGE_TAG     (PKG_DIR holds entropa-gate-VERSION-linux-x86_64.tar.gz and testkeys/ from the build; IMAGE_TAG is the image the build printed)
# The container has no network and only these mounts: the work directory (read-write), the host's minisign program and its one library (read-only). Nothing is pulled and nothing is deleted; every run uses a new work directory.
set -u
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
PKG="${1:?usage: doc-install1.sh PKG_DIR IMAGE_TAG}"; IMG="${2:?usage: doc-install1.sh PKG_DIR IMAGE_TAG}"
GUIDE="$HERE/docs/public-drafts/INSTALL-THE-GATE.md"
BASE="${DOC_INSTALL1_BASE:-rust:1-slim-bookworm}"
TAR=$(ls "$PKG"/entropa-gate-*-linux-x86_64.tar.gz | head -1); V=$(basename "$TAR" | sed 's/^entropa-gate-\(.*\)-linux-x86_64.tar.gz$/\1/')
MS=$(cat "$PKG/testkeys/minisign.pub.line"); ML=$(cat "$PKG/testkeys/mldsa.pub.hex")
W="$(mktemp -d "${TMPDIR:-/tmp}/doc-install1.XXXXXX")"; mkdir -p "$W/work" "$W/out" "$W/home" "$W/home2" "$W/home3" "$W/home4" "$W/data"; chmod 0777 "$W/data"
cp "$TAR" "$W/work/"
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
docker image inspect "$BASE" >/dev/null 2>&1 || { echo "FAIL the local image $BASE is missing (nothing is pulled)"; exit 1; }
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "FAIL the local image $IMG is missing"; exit 1; }
REC='{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"How many claims were denied by payer?","output":"SELECT payer, COUNT(*) FROM t GROUP BY payer LIMIT 100","run_id":"run-s1-a","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":120,"output_tokens":40,"cost_micro_usd":90}'
printf '%s' "$REC" > "$W/record.json"
dk() { # docker run for the base image: $1 = home dir name under /w, then the rest are the sh -c script; extra docker options in DK_OPTS
  local home="$1"; shift
  docker run --rm --network none --pull never ${DK_OPTS:---user "$(id -u):$(id -g)"} -e HOME="/w/$home" -v "$W":/w -v /usr/bin/minisign:/usr/local/bin/minisign:ro -v /usr/lib/x86_64-linux-gnu/libsodium.so.23:/usr/lib/x86_64-linux-gnu/libsodium.so.23:ro "$BASE" sh -c "$@"
}
# 1. the guide's steps 2, 3 and 5 in one clean home
dk home "set -u; cd /w/work && tar -xzf entropa-gate-$V-linux-x86_64.tar.gz && cd entropa-gate-$V
minisign -V -P '$MS' -m SHA256SUMS > /w/out/minisign-verify.txt 2>&1; echo \"exit \$?\" >> /w/out/minisign-verify.txt
sha256sum -c SHA256SUMS > /w/out/sha256check.txt 2>&1; echo \"exit \$?\" >> /w/out/sha256check.txt
sh ./install.sh --minisign-pubkey '$MS' > /w/out/install.txt 2>&1; echo \"exit \$?\" >> /w/out/install.txt
export PATH=\$HOME/.local/bin:\$PATH
entropa-gate init --dir ~/entropa-node > /w/out/init.txt 2>&1; echo \"exit \$?\" >> /w/out/init.txt
ls ~/entropa-node > /w/out/nodefiles.txt 2>&1
stat -c '%a %n' ~/entropa-node/*.key > /w/out/keymodes.txt 2>&1
entropa-gate record --dir ~/entropa-node < /w/record.json > /w/out/record.txt 2>&1; echo \"exit \$?\" >> /w/out/record.txt
entropa-gate verify --dir ~/entropa-node > /w/out/verify.txt 2>&1; echo \"exit \$?\" >> /w/out/verify.txt
sh ~/.local/share/entropa-gate/uninstall.sh > /w/out/uninstall.txt 2>&1; echo \"exit \$?\" >> /w/out/uninstall.txt
if [ -e ~/.local/bin/entropa-gate ]; then echo present; else echo removed; fi > /w/out/after-uninstall-binary.txt
if [ -d ~/entropa-node ] && ls ~/entropa-node/*.key >/dev/null 2>&1; then echo kept; else echo lost; fi > /w/out/after-uninstall-node.txt
"
# 2. the weaker key mode (the guide says it prints a warning)
dk home2 "set -u; cd /w/work/entropa-gate-$V && sh ./install.sh --pubkey '$ML' > /w/out/pubkey-mode.txt 2>&1; echo \"exit \$?\" >> /w/out/pubkey-mode.txt"
# 3. refuses to run as root unless told otherwise
DK_OPTS="--user 0:0" dk home3 "set -u; cd /w/work/entropa-gate-$V && sh ./install.sh --minisign-pubkey '$MS' > /w/out/root.txt 2>&1; echo \"exit \$?\" >> /w/out/root.txt; ls /w/home3/.local 2>/dev/null | wc -l >> /w/out/root.txt"
# 4. a changed file is refused before anything is copied
dk home4 "set -u; cp -r /w/work/entropa-gate-$V /w/tampered && cd /w/tampered && printf 'x' >> entropa-gate && sh ./install.sh --minisign-pubkey '$MS' > /w/out/tamper.txt 2>&1; echo \"exit \$?\" >> /w/out/tamper.txt; ls /w/home4/.local 2>/dev/null | wc -l >> /w/out/tamper.txt"
# 5. the container section, with a host directory in place of the named volume (a named volume would stay on this machine)
{ docker run --rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges --pull never -v "$W/data":/data "$IMG" init --dir /data/node; echo "exit $?"; } > "$W/out/container-init.txt" 2>&1
{ docker run --rm -i --read-only --network none --cap-drop ALL --security-opt no-new-privileges --pull never -v "$W/data":/data "$IMG" record --dir /data/node < "$W/record.json"; echo "exit $?"; } > "$W/out/container-record.txt" 2>&1
{ docker run --rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges --pull never -v "$W/data":/data "$IMG" verify --dir /data/node; echo "exit $?"; } > "$W/out/container-verify.txt" 2>&1
# normalise: the real home becomes /home/you, the real version becomes VERSION, a 64-hex value becomes HEX64 and the key fingerprint becomes FINGERPRINT16 (they differ per release and per key)
for f in "$W"/out/*.txt; do
  sed -i -e "s#/w/home[0-9]*#/home/you#g" -e "s#$V#VERSION#g" -e 's/[0-9a-f]\{64\}/HEX64/g' -e 's/\(of the key text you gave): \)[0-9a-f]\{16\}/\1FINGERPRINT16/' "$f"
done
echo "work directory: $W"
# what the guide promises, written by hand (not copied from a run)
exp() { if [ "$(cat "$W/out/$1.txt")" = "$2" ]; then ok "$1"; else bad "$1: got [$(cat "$W/out/$1.txt")]"; fi; }
has() { if grep -q -F -- "$3" "$W/out/$1.txt"; then ok "$1 $2"; else bad "$1 $2 (no '$3')"; fi; }
exp init $'initialised\nexit 0'
exp verify $'OK records=1 checkpoints=1\nexit 0'
exp nodefiles $'ledger\nplatinum.key'
exp keymodes '600 /home/you/entropa-node/platinum.key'
exp after-uninstall-binary removed
exp after-uninstall-node kept
exp container-init $'initialised\nexit 0'
exp container-verify $'OK records=1 checkpoints=1\nexit 0'
has install "verified by minisign and exit 0" "(verified: minisign)"
has install "exit 0" "exit 0"
has pubkey-mode "warns that the weaker mode is not enough for a hostile download" "WARNING: an attacker who replaced this tarball"
has root "refuses root" "install refused: this is running as root"
has tamper "refuses a changed file" "a file does not match SHA256SUMS"
has uninstall "keeps keys and ledgers" "your keys and ledgers were not touched"
has minisign-verify "signature verifies" "Signature and comment signature verified"
if [ "$(tail -1 "$W/out/root.txt")" = 0 ] && [ "$(tail -1 "$W/out/tamper.txt")" = 0 ]; then ok "nothing was installed by the refused runs"; else bad "something was installed by a refused run"; fi
# the guide: every `<!-- run:NAME -->` block must equal the output captured above, and every NAME captured for the guide must appear in it
if [ ! -f "$GUIDE" ]; then bad "the guide $GUIDE does not exist"; else
python3 - "$GUIDE" "$W/out" <<'PYEOF' || fail=1
import re, sys, pathlib
guide, out = pathlib.Path(sys.argv[1]).read_text(), pathlib.Path(sys.argv[2])
blocks = re.findall(r"<!-- run:([a-z0-9.-]+) -->\n```[a-z]*\n(.*?)\n```", guide, re.S)
names = {b[0] for b in blocks}
bad = 0
for name, text in blocks:
    want = (out / (name + ".txt")).read_text().rstrip("\n")
    if text.rstrip("\n") != want:
        print(f"FAIL the guide block {name} differs:\n--- guide\n{text}\n--- captured\n{want}"); bad = 1
    else:
        print(f"ok   guide block {name}")
need = {"install", "init", "record", "verify", "uninstall", "pubkey-mode", "root", "tamper", "container-init", "container-record", "container-verify", "minisign-verify", "sha256check"}
for m in sorted(need - names):
    print(f"FAIL the guide has no block for {m}"); bad = 1
sys.exit(bad)
PYEOF
fi
if [ "$fail" -eq 0 ]; then echo "ALL OK"; else echo "FAILED (outputs in $W/out)"; fi
exit "$fail"
