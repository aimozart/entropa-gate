#!/usr/bin/env bash
# S1 task 6: install-to-first-record, timed, on a clean temporary directory with the static binary, and again in the container with --network none.
# Steps: init, record 3 events, verify OK, change one byte in a copy and verify FAIL, generate the explorer (OK page, and a FAIL page for the tampered copy),
# licence check OK and FAIL. Prints seconds per step and a result line per step. The licence and its key are a throwaway test pair (examples/issue_test_licence.rs).
# Usage: scripts/s1-install-test.sh   (needs scripts/s1-package.sh to have run)   Env: S1_OUT, S1_RUNS (timed repetitions, default 5)
set -u
cd "$(dirname "$0")/.."
OUT="${S1_OUT:-$HOME/.cache/build/s1-package}"
BIN="$OUT/entropa-gate"
IMG=$(sed -n 's/^image tag: //p' "$OUT/report.txt" | head -1)
RUNS="${S1_RUNS:-5}"
REQ='{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"How many claims were denied by payer?","output":"SELECT 1","run_id":"run-s1-install","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":1,"cost_micro_usd":1}'
fail=0
now() { date +%s.%N; }
secs() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", b-a}'; }
note() { printf '%-44s %s\n' "$1" "$2"; }

mkdir -p target-install-test 2>/dev/null
W=$(mktemp -d "${TMPDIR:-/tmp}/s1-install.XXXXXX")
# the throwaway licence pair
CARGO_NET_OFFLINE=true timeout 900 systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 cargo run --release --offline -q -j2 -p entropa-gate --features issue --example issue_test_licence -- "$W" || { echo "cannot make the test licence"; exit 1; }
printf 'org_name = "Install Test Clinic"\ntiers = ["T0", "T1"]\naccent_color = "#2a7f62"\n' > "$W/config.toml"

run_cycle() { # $1 = label, $2 = how to run the binary: host | container
  local label="$1" mode="$2" dir="$W/$1" ; mkdir -p "$dir"; chmod 700 "$dir"
  local uid; uid="$(id -u):$(id -g)"
  local g
  if [ "$mode" = host ]; then g() { "$BIN" "$@"; }; D="$dir"; else
    g() { docker run -i --name "s1-inst-$label-$RANDOM-$$" --read-only --network none --cap-drop ALL --security-opt no-new-privileges --user "$uid" -v "$dir:/data" -v "$W:/in:ro" "$IMG" "$@"; }; D="/data"; fi
  local T0 t1 t2 t3 t4 t5 t6 t7 t8
  T0=$(now)
  g init --dir "$D/node" >/dev/null 2>&1 || { note "$label init" FAIL; return 1; }; t1=$(now)
  for i in 1 2 3; do echo "$REQ" | g record --dir "$D/node" >/dev/null 2>&1 || { note "$label record $i" FAIL; return 1; }; done; t2=$(now)
  v=$(g verify --dir "$D/node" 2>&1); case "$v" in "OK records=3 checkpoints=3"*) vok=ok ;; *) vok="FAIL: $v" ;; esac; t3=$(now)
  # a copy with one byte changed
  cp -r "$dir/node" "$dir/copy"; f="$dir/copy/ledger/records.log"; len=$(stat -c %s "$f"); python3 - "$f" "$((len / 2))" <<'P'
import sys
p, i = sys.argv[1], int(sys.argv[2])
b = bytearray(open(p, "rb").read()); b[i] = ord("b") if b[i] == ord("a") else ord("a"); open(p, "wb").write(b)
P
  if [ "$mode" = host ]; then Dc="$dir/copy"; else Dc="/data/copy"; fi
  g verify --dir "$Dc" >/dev/null 2>&1 && tok="FAIL (the tampered copy verified)" || tok=ok; t4=$(now)
  if [ "$mode" = host ]; then CFG="$W/config.toml"; else CFG="/in/config.toml"; fi
  g explorer --dir "$D/node" --config "$CFG" --out "$D/site" >/dev/null 2>&1 && grep -q "status-ok" "$dir/site/index.html" && eok=ok || eok="FAIL"; t5=$(now)
  g explorer --dir "$Dc" --config "$CFG" --out "$D/site-tampered" >/dev/null 2>&1; grep -q "status-fail" "$dir/site-tampered/index.html" 2>/dev/null && efail=ok || efail="FAIL"; t6=$(now)
  if [ "$mode" = host ]; then L="$W/licence.json"; K="$W/issuer.pub"; else L=/in/licence.json; K=/in/issuer.pub; fi
  g licence check --file "$L" --pubkey-file "$K" >/dev/null 2>&1 && lok=ok || lok="FAIL"; t7=$(now)
  cp "$W/licence.json" "$dir/licence-bad.json"; python3 - "$dir/licence-bad.json" <<'P'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); i = len(b) // 2; b[i] = ord("b") if b[i] == ord("a") else ord("a"); open(p, "wb").write(b)
P
  if [ "$mode" = host ]; then LB="$dir/licence-bad.json"; else LB=/data/licence-bad.json; fi
  g licence check --file "$LB" --pubkey-file "$K" >/dev/null 2>&1 && lbad="FAIL (a tampered licence was accepted)" || lbad=ok; t8=$(now)
  note "$label: init" "$(secs "$T0" "$t1") s"
  note "$label: record x3" "$(secs "$t1" "$t2") s"
  note "$label: verify (expect OK records=3)" "$(secs "$t2" "$t3") s  $vok"
  note "$label: tampered copy fails" "$(secs "$t3" "$t4") s  $tok"
  note "$label: explorer, intact -> OK page" "$(secs "$t4" "$t5") s  $eok"
  note "$label: explorer, tampered -> FAIL page" "$(secs "$t5" "$t6") s  $efail"
  note "$label: licence check OK" "$(secs "$t6" "$t7") s  $lok"
  note "$label: tampered licence refused" "$(secs "$t7" "$t8") s  $lbad"
  note "$label: TOTAL install to last check" "$(secs "$T0" "$t8") s"
  case "$vok$tok$eok$efail$lok$lbad" in okokokokokok) return 0 ;; *) return 1 ;; esac
}

echo "== host, static binary $(sha256sum "$BIN" | cut -c1-16)..., $RUNS runs"
for n in $(seq 1 "$RUNS"); do run_cycle "host-$n" host || fail=1; done | tee "$W/host.txt"
echo "== container $IMG, --read-only --network none --cap-drop ALL, 1 run"
run_cycle "container-1" container || fail=1
echo "scratch directory left in place: $W"
[ "$fail" = 0 ] && echo "INSTALL TEST: ALL STEPS OK" || echo "INSTALL TEST: A STEP FAILED"
exit "$fail"
