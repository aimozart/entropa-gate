#!/usr/bin/env python3
"""Pre-flight for docs/REAL-CLIENT-TEST.md: drives target/release/entropa-mcp over stdio with a
hand-written JSON-RPC client and the demo fixtures, and prints the key fields of each result.
This is NOT a real-client test (no Claude Code involved); it shows what the real client should see."""
import json, os, subprocess, sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
demo = os.path.join(root, "target", "mcp-demo")
binary = os.path.join(root, "target", "release", "entropa-mcp")
env = dict(os.environ,
           ENTROPA_LOG_FILE=os.path.join(demo, "log.json"),
           ENTROPA_TRUSTED_PUBKEYS=open(os.path.join(demo, "trusted_pubkey.txt")).read().strip())
p = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True)

def rpc(i, method, params=None):
    msg = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        msg["params"] = params
    p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()
    return json.loads(p.stdout.readline())

def load(name):
    return json.load(open(os.path.join(demo, name)))

rpc(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "preflight", "version": "0"}})
p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"); p.stdin.flush()

cases = [
    ("T1 log_head", "log_head", {}),
    ("T2 verify_checkpoint valid", "verify_checkpoint", load("checkpoint-valid.json")),
    ("T3 verify_checkpoint tampered size", "verify_checkpoint", load("checkpoint-tampered.json")),
    ("T4 verify_receipt valid", "verify_receipt", load("receipt-valid.json")),
    ("T5 verify_receipt tampered record", "verify_receipt", load("receipt-tampered.json")),
    ("T6 verify_receipt wrong index", "verify_receipt", load("receipt-wrong-index.json")),
    ("T7 verify_receipt untrusted signer", "verify_receipt", load("receipt-untrusted-signer.json")),
    ("T8 list_records limit 2", "list_records", {"limit": 2}),
    ("T9 explain_proof valid", "explain_proof", load("receipt-valid.json")),
    ("T10 invalid arguments (uppercase hex)", "verify_checkpoint", load("checkpoint-uppercase-hex.json")),
]
keys = ["valid", "signature_valid", "signer_trusted", "inclusion_valid", "root_matches", "size", "total", "next_since_index", "error"]
print(f"{'case':44} {'isError':8} fields")
for n, (label, tool, args) in enumerate(cases, start=2):
    r = rpc(n, "tools/call", {"name": tool, "arguments": args})
    res = r["result"]; body = res["structuredContent"]
    shown = {k: body[k] for k in keys if k in body}
    if "records" in body:
        shown["payloads"] = [x["preview"]["payload_preview"] for x in body["records"]]
    print(f"{label:44} {str(res['isError']).lower():8} {json.dumps(shown)}")
p.stdin.close(); p.wait(timeout=5)
