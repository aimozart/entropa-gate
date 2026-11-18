#!/usr/bin/env bash
# EG1 E4 (no network): run every built egress test binary under strace and count network syscalls. Expect 0 for each.
# Usage: scripts/eg1-strace.sh   (builds the release tests first; the one test that spawns `cargo tree` is skipped: cargo is not the engine)
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true
mapfile -t bins < <(cargo test --release --offline -p entropa-egress --no-run --message-format=json 2>/dev/null | python3 -c '
import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("reason")=="compiler-artifact" and m.get("profile",{}).get("test") and m.get("executable") and "entropa-egress" in m["package_id"]: print(m["executable"])')
total=0
for b in "${bins[@]}"; do
  n=$(EG1_CASES=2000 timeout 900 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 strace -f -qq -e trace=socket,connect,bind,listen,accept,accept4,sendto,sendmsg,sendmmsg,recvfrom,socketpair -o ${TMPDIR:-/tmp}/eg1-strace.$$ "$b" --skip e4_ >/dev/null 2>&1; grep -c -E '^[0-9]+ +(socket|connect|bind|listen|accept4?|sendto|sendmsg|sendmmsg|recvfrom|socketpair)\(' ${TMPDIR:-/tmp}/eg1-strace.$$ || true)
  echo "$(basename "$b"): network syscalls = $n"
  total=$((total + n))
done
echo "TOTAL network syscalls = $total"
[ "$total" -eq 0 ]
