#!/usr/bin/env bash
# AT2 task 6: the no-network check. Every built test binary of entropa-tiers runs under strace -f; any socket, connect, bind, listen, accept, send or receive syscall is counted.
# Expect 0. Usage: scripts/at2-strace.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_NET_OFFLINE=true
mapfile -t bins < <(cargo test --release --offline -p entropa-tiers --no-run --message-format=json 2>/dev/null | python3 -c '
import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("reason")=="compiler-artifact" and m.get("profile",{}).get("test") and m.get("executable") and "entropa-tiers" in m["package_id"]: print(m["executable"])')
total=0
for b in "${bins[@]}"; do
  n=$(timeout 900 systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 strace -f -qq -e trace=socket,connect,bind,listen,accept,accept4,sendto,sendmsg,sendmmsg,recvfrom,socketpair -o /tmp/at2-strace.$$ "$b" >/dev/null 2>&1; grep -c -E '^[0-9]+ +(socket|connect|bind|listen|accept4?|sendto|sendmsg|sendmmsg|recvfrom|socketpair)\(' /tmp/at2-strace.$$ || true)
  echo "$(basename "$b"): network syscalls = $n"
  total=$((total + n))
done
echo "TOTAL network syscalls = $total"
[ "$total" -eq 0 ]
