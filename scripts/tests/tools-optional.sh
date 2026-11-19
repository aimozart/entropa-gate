#!/usr/bin/env bash
# CI-FIX 5: tests that need a program the CI container image does not have (node, minisign) must SKIP loudly when it is missing, FAIL when ENTROPA_REQUIRE_TOOLS=1, and really RUN when it is there.
# The test programs are built once; a missing tool is simulated by running them with an empty PATH. Runs cargo on the host (offline); private tooling.
set -uo pipefail
cd "$(dirname "$0")/../.."
export CARGO_NET_OFFLINE=true RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/build/v5-host-target}"
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
build() { # crate test-name -> prints the test executable
  cargo test --offline --locked -p "$1" --test "$2" --no-run --message-format=json 2>/dev/null | python3 -c '
import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("reason")=="compiler-artifact" and m.get("executable") and m.get("target",{}).get("name")==sys.argv[1]: print(m["executable"])' "$2" | tail -1
}
EMPTY="$(mktemp -d "${TMPDIR:-/tmp}/emptypath.XXXXXX")"
check() { # label crate test-binary-name test-filter
  local label="$1" exe; exe="$(build "$2" "$3")"
  [ -x "$exe" ] || { bad "$label: could not build $3"; return; }
  local out rc
  out="$(cd "$(dirname "$exe")" && env PATH="$EMPTY" "$exe" "$4" --nocapture 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] && ok "$label: without the tool it passes (skips)" || bad "$label: without the tool it failed (rc=$rc): $(echo "$out" | grep -m1 panicked)"
  case "$out" in *"SKIPPED"*) ok "$label: and says SKIPPED";; *) bad "$label: no SKIPPED line";; esac
  out="$(env PATH="$EMPTY" ENTROPA_REQUIRE_TOOLS=1 "$exe" "$4" 2>&1)"; rc=$?
  [ "$rc" -ne 0 ] && ok "$label: ENTROPA_REQUIRE_TOOLS=1 makes a missing tool a failure" || bad "$label: a required tool was not enforced"
  out="$(unset ENTROPA_REQUIRE_TOOLS; "$exe" "$4" --nocapture 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] && ok "$label: with the tool it passes" || bad "$label: with the tool it failed (rc=$rc)"
  case "$out" in *"SKIPPED"*) bad "$label: skipped although the tool is present";; *) ok "$label: and really ran";; esac
}
check "dash1 d3 (node)" entropa-mockview dash1 d3_the_page
check "ls2 l7 (node)" entropa-mockview ls2 l7_app_js
check "ls2_tar t5 (node)" entropa-mockview ls2_tar t5_the_page
check "release s2 x1 (minisign)" entropa-release s2 x1_minisign
exit $fail
