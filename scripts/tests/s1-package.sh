#!/usr/bin/env bash
# S1 task 5 test: the packaging claims, checked on the artifacts that scripts/s1-package.sh builds. Run it after the build (S1_REUSE=1 reuses the last build).
# Checks: the binary is static and runs with no shared libraries; no network syscall in a full run; the Dockerfile is minimal (scratch, numeric non-root user,
# a data volume, no shell, no exposed port); the image runs read-only with no network and no capabilities and completes init, record, verify; the report states
# both SHA-256 values and whether two builds are identical, and does not claim more than it measured.
set -u
cd "$(dirname "$0")/../.."
OUT="${S1_OUT:-$HOME/.cache/build/s1-package}"
fail=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
REQ='{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"How many claims were denied by payer?","output":"SELECT 1","run_id":"run-s1-pkg","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":1,"cost_micro_usd":1}'

[ -x scripts/s1-package.sh ] || { bad "scripts/s1-package.sh is missing or not executable"; exit 1; }
if [ "${S1_REUSE:-0}" != 1 ]; then
  mkdir -p "$OUT"
  timeout 3000 scripts/s1-package.sh > "$OUT.build.log" 2>&1 || bad "scripts/s1-package.sh failed (see $OUT.build.log)"
fi
BIN="$OUT/entropa-gate"; REPORT="$OUT/report.txt"
[ -x "$BIN" ] && ok "binary exists" || { bad "no binary at $BIN"; exit 1; }
[ -f "$REPORT" ] && ok "report exists" || { bad "no report at $REPORT"; exit 1; }

# P1: static
desc=$(file -b "$BIN")
case "$desc" in *"statically linked"*|*"static-pie linked"*) ok "static: $desc" ;; *) bad "not static: $desc" ;; esac
needed=$(readelf -d "$BIN" 2>/dev/null | grep -c '(NEEDED)' || true)
[ "$needed" = 0 ] && ok "no shared library is needed" || bad "$needed shared libraries needed"
sha=$(sha256sum "$BIN" | cut -d' ' -f1)
grep -q "binary sha256: $sha" "$REPORT" && ok "report sha256 matches the file" || bad "report sha256 does not match $sha"

# P1: runs, and makes no network syscall in a full cycle
tmp=$(mktemp -d "${TMPDIR:-/tmp}/s1-pkg-test.XXXXXX")
trace="$tmp/strace.txt"
run() { strace -f -qq -e trace=network -o "$trace.$RANDOM" "$BIN" "$@"; }
node="$tmp/node"
if "$BIN" init --dir "$node" >/dev/null 2>&1 && for i in 1 2 3; do echo "$REQ" | "$BIN" record --dir "$node" >/dev/null 2>&1 || exit 1; done && "$BIN" verify --dir "$node" 2>&1 | grep -q '^OK records=3'; then ok "init, 3 records, verify on the static binary"; else bad "the static binary does not complete init, record, verify"; fi
node2="$tmp/node2"
strace -f -qq -e trace=socket,connect,bind,listen,accept,accept4,sendto,sendmsg,recvfrom,socketpair -o "$trace" sh -c "'$BIN' init --dir '$node2' && echo '$REQ' | '$BIN' record --dir '$node2' && '$BIN' verify --dir '$node2'" >/dev/null 2>&1
n=$(grep -c -E '^[0-9]+ +(socket|connect|bind|listen|accept4?|sendto|sendmsg|recvfrom|socketpair)\(' "$trace" || true)
[ "$n" = 0 ] && ok "0 network syscalls in a full cycle" || bad "$n network syscalls"

# P2: the build file
DF=packaging/Dockerfile
[ -f "$DF" ] || { bad "$DF is missing"; }
if [ -f "$DF" ]; then
  grep -q '^FROM scratch' "$DF" && ok "FROM scratch" || bad "the image is not FROM scratch"
  grep -Eq '^USER [1-9][0-9]*:[1-9][0-9]*' "$DF" && ok "numeric non-root USER" || bad "no numeric non-root USER"
  grep -q '^VOLUME' "$DF" && ok "a data volume" || bad "no VOLUME"
  grep -Eq '^(RUN|SHELL|EXPOSE|ADD http|HEALTHCHECK CMD-SHELL)' "$DF" && bad "a RUN, SHELL, EXPOSE or remote ADD is present" || ok "no RUN, SHELL, EXPOSE or remote ADD"
  grep -Eq '^ENTRYPOINT \["/entropa-gate"\]' "$DF" && ok "exec-form entrypoint, no shell" || bad "the entrypoint is not the binary in exec form"
fi

# P2: the image
IMG=$(sed -n 's/^image tag: //p' "$REPORT" | head -1)
if [ -n "$IMG" ] && docker image inspect "$IMG" >/dev/null 2>&1; then
  ok "image $IMG exists"
  user=$(docker image inspect --format '{{.Config.User}}' "$IMG")
  case "$user" in 0|root|"") bad "the image user is '$user'" ;; *) ok "image user $user" ;; esac
  cid="s1-pkg-test-$$-$RANDOM"
  data="$tmp/data"; mkdir -p "$data"; chmod 700 "$data"
  uid="$(id -u):$(id -g)"
  d() { docker run --name "$cid-$1" --read-only --network none --cap-drop ALL --security-opt no-new-privileges --user "$uid" -v "$data:/data" "$IMG" "${@:2}"; }
  d init init --dir /data/node >/dev/null 2>&1 && ok "container init" || bad "container init"
  for i in 1 2 3; do echo "$REQ" | docker run -i --name "$cid-rec$i" --read-only --network none --cap-drop ALL --security-opt no-new-privileges --user "$uid" -v "$data:/data" "$IMG" record --dir /data/node >/dev/null 2>&1 || bad "container record $i"; done
  d verify verify --dir /data/node 2>&1 | grep -q '^OK records=3' && ok "container verify OK records=3" || bad "container verify"
  # the root filesystem is read-only: a write outside the volume must fail
  if d rofs init --dir /not-the-volume/node >/dev/null 2>&1; then bad "the container wrote outside the volume"; else ok "a write outside the volume is refused"; fi
  # no network: the container has none (the run above used --network none and worked)
else
  bad "no image: the report names '$IMG'"
fi

# P3, P4: the report states both hashes and the reproducibility result without hiding a difference
grep -Eq '^binary sha256: [0-9a-f]{64}$' "$REPORT" && ok "binary sha256 line" || bad "no binary sha256 line"
grep -Eq '^second build sha256: [0-9a-f]{64}$' "$REPORT" && ok "second build sha256 line" || bad "no second build sha256 line"
grep -Eq '^image id: sha256:[0-9a-f]{64}$' "$REPORT" && ok "image id line" || bad "no image id line"
r=$(sed -n 's/^reproducible: //p' "$REPORT" | head -1)
a=$(sed -n 's/^binary sha256: //p' "$REPORT" | head -1); b=$(sed -n 's/^second build sha256: //p' "$REPORT" | head -1)
case "$r" in
  yes*) [ "$a" = "$b" ] && ok "reproducible: yes, and the two hashes are equal" || bad "the report says reproducible but the hashes differ" ;;
  no*)  [ "$a" != "$b" ] && grep -q '^difference: ' "$REPORT" && ok "reproducible: no, hashes differ and a difference is explained" || bad "the report says not reproducible without evidence" ;;
  *)    bad "no reproducible line" ;;
esac
grep -qi -E 'tamper-proof|secure|compliant|certified' "$REPORT" && bad "the report makes a claim it did not measure" || ok "no unmeasured claim in the report"
[ "$fail" = 0 ] && echo "ALL PACKAGING CHECKS PASSED" || echo "PACKAGING CHECKS FAILED"
exit "$fail"
