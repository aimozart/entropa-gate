#!/usr/bin/env python3
"""R1 live demonstration: run the real entropa-standards-mcp over stdio on the real sealed corpus, INSIDE an empty network namespace (unshare -rn),
make a handful of retrievals, then verify the signed records offline. Writes docs/evidence/r1/mcp-live-run.json (ids, codes and sentences only).
Usage: scripts/r1-live-mcp-demo.py  (needs target/release binaries, the sealed store and the R1 scratch node; all outside the repo)"""
import json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOME = Path.home() / ".cache" / "build"
STORE, NODE = HOME / "standards-store", HOME / "r1-scratch-node"
BIN, PLAT = ROOT / "target/release/entropa-standards-mcp", ROOT / "target/release/entropa-platinum"
VERSION = "c2026-11-13"
manifest = json.loads((ROOT / "docs/evidence/r1/manifest-c2026-11-13.json").read_text())
h = {(c["standard"], c["id"]): c["text_sha256"] for c in manifest["clauses"]}

env = dict(os.environ, ENTROPA_STANDARDS_STORE=str(STORE), ENTROPA_STANDARDS_VERSIONS=VERSION, ENTROPA_PLATINUM_BIN=str(PLAT), ENTROPA_NODE_DIR=str(NODE))
p = subprocess.Popen(["unshare", "-rn", str(BIN)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
def send(o): p.stdin.write(json.dumps(o) + "\n"); p.stdin.flush()
def recv(): return json.loads(p.stdout.readline())
send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "demo", "version": "0"}}}); recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
calls = [
 ("search", {"query": "What does NIST SP 800-53 control AU-9(3) require?"}),
 ("search", {"query": "Which PCI DSS requirement requires an incident response plan that is ready to be activated?"}),
 ("search", {"query": "What does SOC 2 criterion CC6.1 require for logical access?"}),
 ("lookup_clause", {"standard": "PCI-DSS", "clause": "10.3.4"}),
 ("cite_check", {"standard": "PCI-DSS", "clause": "10.3.4", "version": VERSION, "hash": h[("PCI-DSS", "10.3.4")]}),
 ("cite_check", {"standard": "PCI-DSS", "clause": "10.3.4", "version": VERSION, "hash": "f" * 64}),
 ("list_versions", {}),
]
log = []
for i, (name, args) in enumerate(calls, start=2):
    send({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}})
    r = recv()["result"]; sc = r["structuredContent"]
    top = (sc.get("passages") or [{}])[0].get("clause_id") if "passages" in sc else None
    q = sc.get("passage", {}).get("quote") if "passage" in sc else None
    log.append(dict(tool=name, outcome=sc.get("verdict") or sc.get("error") or ("listed" if "versions" in sc else "found"), top_clause=top, licensed_quote_words=len(q.split()) if q else None))
p.stdin.close(); rc = p.wait()
ver = subprocess.run([str(PLAT), "verify-evidence", str(NODE)], capture_output=True, text=True).stdout.strip().splitlines()[-1]
exp = json.loads(subprocess.run([str(PLAT), "export-evidence", str(NODE)], capture_output=True, text=True).stdout)
recs = [dict(index=r["index"], label=r["label"], plain=r["plain"]) for r in exp["records"] if r["label"] == "retrieval_record"]
out = dict(evidence_kind="mcp_live_run", corpus_version=VERSION, run_under="unshare -rn (an empty network namespace: no interface but loopback-less)", server_exit_status=rc, calls=log, node_verify=ver, retrieval_records=recs,
           note="the corpus and the node are outside the repository; only closed codes and sentences are recorded here")
(ROOT / "docs/evidence/r1/mcp-live-run.json").write_text(json.dumps(out, indent=1) + "\n")
print(json.dumps({k: out[k] for k in ("server_exit_status", "node_verify")}), len(recs), "retrieval records")
for c in log: print(c)
for r in recs: print(r["index"], r["plain"])
