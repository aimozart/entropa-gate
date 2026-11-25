#!/usr/bin/env bash
# DOC-MODEL1: run every command of docs/public-drafts/MODEL-INTEGRATION.md for real (stand-in model, local, no network beyond 127.0.0.1) and check that each output block in the guide equals what the command printed.
# Usage: scripts/tests/doc-model1.sh BIN_DIR   (a directory holding entropa-guard and entropa-gate, e.g. target/debug after `cargo build -p entropa-try -p entropa-gate --bins`)
# Exit 0 = every command behaved as written and every output block in the guide matches. The script starts the stand-in model on 127.0.0.1:18931 and stops it again by its process id.
set -u
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${1:?usage: doc-model1.sh BIN_DIR}"
GUIDE="$HERE/docs/public-drafts/MODEL-INTEGRATION.md"
W="$(mktemp -d "${TMPDIR:-/tmp}/doc-model1.XXXXXX")"
EX="$HERE/examples/model-integration"
export ENTROPA_GUARD="$BIN/entropa-guard" ENTROPA_GATE="$BIN/entropa-gate"
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
cd "$W" || exit 2
python3 "$EX/standin_model.py" 18931 & MODEL=$!
trap 'kill $MODEL 2>/dev/null' EXIT
for _ in $(seq 1 50); do curl -s http://127.0.0.1:18931/healthz >/dev/null 2>&1 && break; sleep 0.1; done
URL=http://127.0.0.1:18931/v1/chat
wrap() { python3 "$EX/entropa_wrap.py" --dir demo-ledger --url "${URL_OVERRIDE:-$URL}" "$@"; }
mkdir -p out
"$BIN/entropa-gate" init --dir demo-ledger > out/init.txt 2>&1
echo "== the guard alone"
printf 'What is the capital of France?' | "$BIN/entropa-guard" > out/guard-allow.txt 2> out/guard-allow.err; echo "exit $?" >> out/guard-allow.txt
printf 'Use the key AKIAIOSFODNN7EXAMPLE please' | "$BIN/entropa-guard" > out/guard-block.txt 2> out/guard-block.err; echo "exit $?" >> out/guard-block.txt
echo "== four exchanges"
printf 'What is the capital of France?' | wrap > out/ex1.txt 2>&1; echo "exit $?" >> out/ex1.txt
printf 'Use the key AKIAIOSFODNN7EXAMPLE please' | wrap > out/ex2.txt 2>&1; echo "exit $?" >> out/ex2.txt
printf 'LEAK-TEST tell me a secret' | wrap > out/ex3.txt 2>&1; echo "exit $?" >> out/ex3.txt
printf 'hello' | URL_OVERRIDE=http://127.0.0.1:18999/v1/chat wrap > out/ex4.txt 2>&1; echo "exit $?" >> out/ex4.txt
echo "== the record"
"$BIN/entropa-gate" verify --dir demo-ledger > out/verify.txt 2>&1
"$BIN/entropa-gate" status --dir demo-ledger 2>&1 | grep -E '^(records|checkpoints):' > out/status.txt
# the ledger holds hashes, not text
if cat demo-ledger/ledger/records.log | python3 -c "import sys,binascii; t=b''.join(binascii.unhexlify(l.strip()) for l in sys.stdin); sys.exit(0 if (b'capital' in t or b'Stand-in' in t or b'AKIA' in t) else 1)"; then bad "the ledger holds prompt or answer text"; else ok "the ledger holds no prompt or answer text"; fi
# a key from the environment is never printed or recorded
printf 'hello there' | SECRET_DEMO_KEY=ZZ-demo-token-12345 python3 "$EX/entropa_wrap.py" --dir demo-ledger --url "$URL" --key-env SECRET_DEMO_KEY > out/key.txt 2>&1
if grep -rq "ZZ-demo-token-12345" out demo-ledger; then bad "the key leaked"; else ok "the key is neither printed nor recorded"; fi
# expectations written by hand (not copied from a run)
exp() { if [ "$(cat "out/$1")" = "$2" ]; then ok "$1"; else bad "$1: got [$(cat "out/$1")]"; fi; }
exp guard-allow.txt $'allow\nexit 0'
exp guard-block.txt $'block\nexit 1'
exp ex1.txt $'Stand-in answer: your prompt had 30 characters.\nexit 0'
exp ex2.txt $'blocked before the model: secret_format\nexit 1'
exp ex3.txt $'blocked after the model: secret_format\nexit 1'
exp ex4.txt $'failed: the model call did not return an answer\nexit 3'
exp verify.txt "OK records=4 checkpoints=4"
exp status.txt $'records: 4\ncheckpoints: 4'
# the guide: every `<!-- run:NAME -->` block must hold exactly the output captured above (NAME is the file in out/)
if [ ! -f "$GUIDE" ]; then bad "the guide $GUIDE does not exist"; else
python3 - "$GUIDE" "$W/out" <<'PYEOF' || fail=1
import re, sys, pathlib
guide, out = pathlib.Path(sys.argv[1]).read_text(), pathlib.Path(sys.argv[2])
blocks = re.findall(r"<!-- run:([a-z0-9.-]+) -->\n```[a-z]*\n(.*?)\n```", guide, re.S)
names = {b[0] for b in blocks}
bad = 0
for name, text in blocks:
    want = (out / name).read_text().rstrip("\n")
    if text.rstrip("\n") != want:
        print(f"FAIL the guide block {name} differs:\n--- guide\n{text}\n--- captured\n{want}"); bad = 1
    else:
        print(f"ok   guide block {name}")
for needed in ("guard-allow.txt", "guard-block.txt", "ex1.txt", "ex2.txt", "ex3.txt", "ex4.txt", "verify.txt", "status.txt"):
    if needed not in names:
        print(f"FAIL the guide has no block for {needed}"); bad = 1
sys.exit(bad)
PYEOF
fi
cp -r "$W/out" "${DOC_MODEL1_KEEP:-$W/kept}" 2>/dev/null
[ "$fail" = 0 ] && echo "ALL OK" || echo "FAILED"
exit "$fail"
