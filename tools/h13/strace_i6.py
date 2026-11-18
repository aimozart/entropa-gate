#!/usr/bin/env python3
"""H1.3 I6 on the real binary: start entropa-standards-mcp under strace -f against a scratch node and the real sealed store (opened read-only),
send normal and hostile calls over the MCP stdio protocol, then classify every file and network syscall. Prints counts and path CLASSES only
(never a query, never clause text). Stdlib only. Exit code 1 if any invariant is violated.
usage: strace_i6.py REPO STORE VERSION SCRATCH_DIR OUT_JSON"""
import json, os, re, subprocess, sys, time, pathlib

repo, store, version, scratch, out_json = sys.argv[1:6]
repo = pathlib.Path(repo); scratch = pathlib.Path(scratch); scratch.mkdir(parents=True, exist_ok=True)
node = scratch / "node"
plat = repo / "target/release/entropa-platinum"
mcp = repo / "target/release/entropa-standards-mcp"
if not node.exists():
    subprocess.run([str(plat), "init", str(node)], check=True, stdout=subprocess.DEVNULL)
log = scratch / "strace.log"
env = dict(os.environ, ENTROPA_STANDARDS_STORE=store, ENTROPA_STANDARDS_VERSIONS=version,
           ENTROPA_PLATINUM_BIN=str(plat), ENTROPA_NODE_DIR=str(node))
trace = "openat,open,creat,mkdir,mkdirat,rename,renameat,renameat2,unlink,unlinkat,rmdir,truncate,ftruncate,symlink,link,chmod,connect,socket,bind,sendto,sendmsg,execve"
p = subprocess.Popen(["strace", "-f", "-s", "160", "-e", f"trace={trace}", "-o", str(log), str(mcp)], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, bufsize=1)
def send(o): p.stdin.write(json.dumps(o) + "\n"); p.stdin.flush()
def recv():
    return json.loads(p.stdout.readline())
send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "i6", "version": "0"}}})
recv(); send({"jsonrpc": "2.0", "method": "notifications/initialized"})
calls = [
    ("list_versions", {}), ("search", {"query": "audit log retention and protection of audit information"}),
    ("search", {"query": "What does NIST SP 800-53 control AC-2 (4) require?"}), ("search", {"query": "Which team won the baseball world series?"}),
    ("search", {"query": "What does PCI DSS requirement 8.3.6 say?"}), ("search", {"query": "164.320(a) ‮​\u0000 ../../../../etc/passwd"}),
    ("lookup_clause", {"standard": "NIST-SP-800-53", "clause": "AC-2"}), ("lookup_clause", {"standard": "../../etc", "clause": "x"}),
    ("lookup_clause", {"standard": "PCI-DSS", "clause": "8.3.6"}),
    ("cite_check", {"standard": "NIST-SP-800-53", "clause": "AC-2", "version": version, "hash": "0" * 64}),
    ("nonexistent_tool", {"x": 1}), ("search", {"query": "x" * 5000}), ("search", {"query": "ok", "k": 99}),
]
for i, (n, a) in enumerate(calls, start=10):
    send({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": n, "arguments": a}})
    while True:
        r = recv()
        if r.get("id") == i:
            break
p.stdin.close(); p.wait(timeout=30)
time.sleep(0.5)

home = str(pathlib.Path.home())
allowed_read = [store, str(node), str(repo / "target/release"), "/lib", "/usr/lib", "/lib64", "/etc/ld.so", "/etc/localtime", "/etc/ssl",
                "/proc/self", "/proc/sys", "/proc/cpuinfo", "/proc/meminfo", "/sys/devices/system/cpu", "/sys/fs/cgroup", "/dev/urandom",
                "/dev/null", "/dev/tty", "/usr/share/zoneinfo", "/etc/nsswitch", "/etc/passwd", "/etc/resolv", "/etc/hosts", "/etc/gai",
                "/sys/kernel/mm/transparent_hugepage", "/proc/stat", "/proc/self/maps"]
def klass(path):
    if path.startswith(str(node)): return "node"
    if path.startswith(store): return "store"
    if path.startswith(str(repo / "target/release")): return "binaries"
    if any(path.startswith(a) for a in allowed_read): return "system"
    return "OTHER"
counts = {"opens": {}, "write_opens": {}, "mutations": {}, "network": [], "exec": []}
violations = []
for line in log.read_text(errors="replace").splitlines():
    m = re.match(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?(\w+)\((.*)", line)
    if not m: continue
    sc, rest = m.group(1), m.group(2)
    if "= -1" in line and sc not in ("connect", "socket"): continue
    if sc in ("openat", "open", "creat"):
        pm = re.search(r'"((?:[^"\\]|\\.)*)"', rest)
        if not pm: continue
        path = pm.group(1)
        wr = bool(re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND", rest)) or sc == "creat"
        k = klass(path)
        counts["opens"][k] = counts["opens"].get(k, 0) + 1
        if wr:
            counts["write_opens"][k] = counts["write_opens"].get(k, 0) + 1
            if k not in ("node", "system") or (k == "system" and not path.startswith("/dev/null")):
                violations.append(("write outside the node directory", k))
        if k == "OTHER": violations.append(("read outside the store, node, binaries and system", path[:60]))
    elif sc in ("mkdir", "mkdirat", "rename", "renameat", "renameat2", "unlink", "unlinkat", "rmdir", "truncate", "symlink", "link", "chmod"):
        pm = re.findall(r'"((?:[^"\\]|\\.)*)"', rest)
        for path in pm[:2]:
            k = klass(path)
            counts["mutations"][k] = counts["mutations"].get(k, 0) + 1
            if k != "node": violations.append(("file mutation outside the node directory", k))
    elif sc in ("connect", "socket", "bind", "sendto", "sendmsg"):
        if re.search(r"AF_INET6?\b|sin_addr|sin6_addr", rest):
            counts["network"].append(sc); violations.append(("network", sc))
        elif "AF_UNIX" in rest or "AF_NETLINK" in rest:
            counts.setdefault("local_sockets", []).append(sc)
    elif sc == "execve":
        pm = re.search(r'"((?:[^"\\]|\\.)*)"', rest)
        if pm:
            b = pm.group(1); counts["exec"].append(os.path.basename(b))
            if os.path.basename(b) not in ("entropa-standards-mcp", "entropa-platinum"):
                violations.append(("exec", os.path.basename(b)))
records = len(list((node / "evidence-ledger").glob("*"))) if (node / "evidence-ledger").exists() else None
rep = {"calls": len(calls), "counts": {k: v for k, v in counts.items() if k != "exec"}, "exec": sorted(set(counts["exec"])),
       "network_syscalls": len(counts["network"]), "violations": sorted(set(map(str, violations))), "store_opened_read_only": counts["write_opens"].get("store", 0) == 0}
pathlib.Path(out_json).write_text(json.dumps(rep, indent=1) + "\n")
print(json.dumps(rep, indent=1))
sys.exit(1 if violations else 0)
