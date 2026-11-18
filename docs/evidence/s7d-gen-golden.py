#!/usr/bin/env python3
"""Independent generator of the S7d golden API responses (no Rust involved).
Reads crates/explorer/tests/golden/bundle_seed1_n5.json, writes crates/explorer/tests/golden/responses.json
({target: canonical body}). Run: python3 docs/evidence/s7d-gen-golden.py
Contract (docs/ARCHITECTURE-EXPLORER.md, S7d): bodies are compact JSON with keys sorted at every level."""
import json, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "crates/explorer/tests/golden"
b = json.loads((root / "bundle_seed1_n5.json").read_text())

def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def page(items, cursor, limit):
    """Newest first; cursor is the exclusive upper position; next_cursor is the lowest position returned, or null."""
    upper = len(items) if cursor is None else cursor
    lo = max(0, upper - limit)
    out = [(i, items[i]) for i in range(upper - 1, lo - 1, -1)]
    return [x for _, x in out], (lo if lo > 0 else None)

def summary(r):
    return {k: r[k] for k in ("handle", "index", "kind", "summary", "tenant", "ts")}

out = {}
n = len(b["records"])
out["/api/healthz"] = canon({"status": "ok"})
out["/api/head"] = canon({"checkpoint": b["head"], "log": b["log"], "size": b["head"]["size"], "synthetic": True})
items, nxt = page(b["checkpoints"], None, 20)
out["/api/checkpoints"] = canon({"items": items, "next_cursor": nxt})
items, nxt = page(b["checkpoints"], None, 1)
out["/api/checkpoints?limit=1"] = canon({"items": items, "next_cursor": nxt})
items, nxt = page([summary(r) for r in b["records"]], None, 20)
out["/api/records"] = canon({"items": items, "next_cursor": nxt})
items, nxt = page([summary(r) for r in b["records"]], 5, 3)
out["/api/records?cursor=5&limit=3"] = canon({"items": items, "next_cursor": nxt})
for t in ("entropa", "bigironbank", "hippagrchealthcare"):
    sel = [summary(r) for r in b["records"] if r["tenant"] == t]
    items, nxt = page(sel, None, 20)
    # filtered pages: cursor is the record index, so recompute against positions of the filtered list
    out[f"/api/records?tenant={t}"] = canon({"items": items, "next_cursor": None if nxt is None else sel[nxt]["index"]})
    out[f"/api/feeds/{t}"] = canon({"items": items, "tenant": t})
sel = [summary(r) for r in b["records"] if r["kind"] == "policy.decision"]
items, _ = page(sel, None, 20)
out["/api/records?kind=policy.decision"] = canon({"items": items, "next_cursor": None})
for i in (0, 12, n - 1):
    out[f"/api/records/{i}"] = canon(b["records"][i])
    rc = b["receipts"][i]
    out[f"/api/receipts/{i}"] = canon({"checkpoint": b["head"], "index": rc["index"], "proof": rc["proof"], "record_hex": b["records"][i]["record_hex"]})
c = b["consistency"][0]
out[f"/api/consistency?old={c['old_size']}&new={c['new_size']}"] = canon(c)
out["/api/witnesses"] = canon({"items": [json.loads(w) for w in b["witnesses"]]})
last = b["head"]["size"]
out[f"/api/witnesses?size={last}"] = canon({"items": [json.loads(w) for w in b["witnesses"] if json.loads(w)["size"] == last]})
out["/api/actors"] = canon({"items": b["actors"]})
for a in b["actors"]:
    mine = [r for r in b["records"] if r["handle"] == a["handle"]]
    kinds = {}
    for r in mine:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    out[f"/api/actors/{a['handle']}"] = canon({"actor": a, "kinds": kinds, "records": len(mine)})
(root / "responses.json").write_text(canon(out))
print(len(out), "golden responses")
