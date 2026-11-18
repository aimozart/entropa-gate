#!/usr/bin/env bash
# Read-only smoke check against the live deployed Entropa service. Every request here
# is a GET - never touches consensus/persistence code, never resets the soak clock.
# Encodes, as an executable check, the exact claims made by hand throughout tonight's
# soak monitoring: the chain is alive, height climbs, and full cryptographic
# verification (Chain::verify(), via the real Rust logic, not a shell approximation)
# passes against the actual live data.
set -euo pipefail

BASE_URL="${ENTROPA_BASE_URL:-https://scryon.entropa.space}"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

fail() { echo "FAIL: $1"; exit 1; }

echo "Checking $BASE_URL/api/health ..."
health1="$(curl -sf "$BASE_URL/api/health")" || fail "could not reach /api/health"
status="$(echo "$health1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])')"
height1="$(echo "$health1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["height"])')"
[ "$status" = "ok" ] || fail "/api/health status=$status (expected ok)"
echo "PASS: /api/health status=ok, height=$height1"

echo "Waiting 10s to confirm block production is live (height must climb, not stall)..."
sleep 10
health2="$(curl -sf "$BASE_URL/api/health")" || fail "could not reach /api/health on second check"
height2="$(echo "$health2" | python3 -c 'import json,sys;print(json.load(sys.stdin)["height"])')"
[ "$height2" -gt "$height1" ] || fail "chain height did not increase in 10s ($height1 -> $height2)"
echo "PASS: chain height climbed ($height1 -> $height2), block production is live"

echo "Fetching head block via /api/head ..."
head_block="$(curl -sf "$BASE_URL/api/head")" || fail "could not reach /api/head"
head_index="$(echo "$head_block" | python3 -c 'import json,sys;print(json.load(sys.stdin)["index"])')"
echo "PASS: /api/head returned block index=$head_index"

echo "Fetching full chain (paginated, with backoff on 429) for real cryptographic verification..."
python3 - "$BASE_URL" "$SCRATCH/chain.json" <<'PYEOF'
import json, sys, time, urllib.request

base_url, out_path = sys.argv[1], sys.argv[2]
blocks, offset, limit = [], 0, 2000

while True:
    url = f"{base_url}/api/chain?limit={limit}&offset={offset}"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                page = json.loads(resp.read())
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    if not page:
        break
    blocks.extend(page)
    offset += limit
    time.sleep(0.3)
    if len(page) < limit:
        break

with open(out_path, "w") as f:
    json.dump(blocks, f)
print(f"fetched {len(blocks)} blocks")
PYEOF

echo "Running full Chain::verify() against fetched data (real Rust crypto logic, not a shell approximation)..."
cd "$(dirname "$0")/.."
verify_output="$(cargo run --release --example verify_backup -p entropa-core -- "$SCRATCH/chain.json" 2>&1)"
echo "$verify_output" | grep -q "VERIFY OK" || fail "Chain::verify() did not report VERIFY OK:\n$verify_output"
echo "PASS: Chain::verify() — every block's hash link and ML-DSA signature checks out"

echo ""
echo "All checks passed. Live chain is up, producing blocks, and cryptographically verified."
