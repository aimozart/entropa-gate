#!/usr/bin/env bash
# CI-FIX 5: the dashboard page tests d3 and d8 run the page's JavaScript with `node`, which the CI container image does not have. Without node they must SKIP, loudly (a SKIPPED line), unless ENTROPA_REQUIRE_NODE=1 says node is required (then they fail);
# with node they run for real. ENTROPA_NODE names the node program (default: node), so "node is missing" can be simulated here. Runs cargo on the host (offline); private tooling.
set -uo pipefail
cd "$(dirname "$0")/../.."
export CARGO_NET_OFFLINE=true RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/build/v5-host-target}"
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
t() { timeout 900 cargo test --offline --locked -p entropa-mockview --test dash1 d3_the_page -- --nocapture 2>&1; }
out="$(ENTROPA_NODE=/no/such/node t)"; rc=$?
[ "$rc" -eq 0 ] && ok "1 without node the page test passes (skips)" || bad "1 without node it failed (rc=$rc)"
case "$out" in *"SKIPPED"*"node"*) ok "1 and says SKIPPED because node is missing";; *) bad "1 no SKIPPED line";; esac
out="$(ENTROPA_NODE=/no/such/node ENTROPA_REQUIRE_NODE=1 t)"; rc=$?
[ "$rc" -ne 0 ] && ok "2 with ENTROPA_REQUIRE_NODE=1 a missing node fails the test" || bad "2 a required node was not enforced"
out="$(unset ENTROPA_NODE ENTROPA_REQUIRE_NODE; t)"; rc=$?
[ "$rc" -eq 0 ] && ok "3 with node the page test passes" || bad "3 with node it failed (rc=$rc)"
case "$out" in *"SKIPPED"*) bad "3 skipped although node is present";; *) ok "3 and really ran (no SKIPPED)";; esac
exit $fail
