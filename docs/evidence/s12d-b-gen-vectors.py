#!/usr/bin/env python3
"""Independent generator of the S12d-b golden vectors (no Rust involved).
Run from the repository root: uv run --offline --with blake3 python3 docs/evidence/s12d-b-gen-vectors.py
Writes crates/council/tests/vectors/memory_v1.json. Definitions (docs/ARCHITECTURE-MEMORY.md sections 4 and 8):
  scorer      score(q, d) = floor(1000 * W(q & d) / W(q | d)), W sums integer field weights (field = text before '=')
  descriptor  canonical JSON (sorted keys, compact) of {"threshold": T, "weights": {field: w}}
  index hash  = BLAKE3("entropa-council-index-l-v1" 0x00 || u32be(len(desc)) desc || u32be(n)
                || for each precedent in sorted id order: u32be(len id) id || u32be(len tenant) tenant
                   || u32be(term count) || for each term in sorted order: u32be(len) term)
  manifest    = BLAKE3("entropa-council-manifest-v1" 0x00 || u32be(n_admitted) || sorted ids (u32be(len) id)
                || u32be(n_revoked) || sorted revoked ids (u32be(len) id))
  memory hash = BLAKE3("entropa-council-memory-v1" 0x00 || index_hash (64 ASCII hex bytes) || sorted ids (u32be(len) id))
"""
import json, pathlib, struct
from blake3 import blake3

def u32(n): return struct.pack(">I", n)
def part(s): b = s.encode(); return u32(len(b)) + b

WEIGHTS = {"class": 4, "decision": 3, "severity": 2, "change": 2, "reason": 1}
THRESHOLD = 400
def descriptor(weights, threshold):
    return json.dumps({"threshold": threshold, "weights": weights}, sort_keys=True, separators=(",", ":"))

def weight(term, weights): return weights.get(term.split("=")[0], 1)
def score(q, d, weights):
    q, d = set(q), set(d)
    inter = sum(weight(t, weights) for t in q & d)
    union = sum(weight(t, weights) for t in q | d)
    return 1000 * inter // union if union else 0

def index_hash(precs, weights, threshold):
    h = blake3(b"entropa-council-index-l-v1\x00")
    h.update(part(descriptor(weights, threshold)))
    h.update(u32(len(precs)))
    for p in sorted(precs, key=lambda p: p["id"].encode()):
        h.update(part(p["id"]) + part(p["tenant"]) + u32(len(p["terms"])))
        for t in sorted(p["terms"], key=lambda t: t.encode()):
            h.update(part(t))
    return h.hexdigest()

def manifest_hash(admitted, revoked):
    h = blake3(b"entropa-council-manifest-v1\x00")
    for group in (admitted, revoked):
        h.update(u32(len(group)))
        for i in sorted(group, key=lambda s: s.encode()):
            h.update(part(i))
    return h.hexdigest()

def memory_hash(idx_hash, ids):
    h = blake3(b"entropa-council-memory-v1\x00")
    h.update(idx_hash.encode())
    for i in sorted(ids, key=lambda s: s.encode()):
        h.update(part(i))
    return h.hexdigest()

P = [
    {"id": "p1", "tenant": "entropa", "terms": ["change=test", "class=missing_approval", "decision=accept", "reason=evidence_sufficient", "severity=high"]},
    {"id": "p2", "tenant": "entropa", "terms": ["change=cedar_change", "class=policy_gap", "decision=accept", "reason=risk_accepted", "severity=medium"]},
    {"id": "p3", "tenant": "bigironbank", "terms": ["change=lesson", "class=missing_approval", "decision=accept", "reason=already_handled", "severity=low"]},
    {"id": "p9", "tenant": "entropa", "terms": ["change=test", "class=wrong_subject", "decision=accept", "reason=evidence_sufficient", "severity=high"]},
]
REVOKED = ["p9"]
admitted = [p for p in P if p["id"] not in REVOKED]
ih = index_hash(admitted, WEIGHTS, THRESHOLD)

def search(tenant, q, k, threshold, weights=WEIGHTS):
    hits = [(p["id"], score(q, p["terms"], weights)) for p in admitted if p["tenant"] == tenant]
    hits = [h for h in hits if h[1] >= threshold]
    hits.sort(key=lambda h: (-h[1], h[0].encode()))
    return [{"id": i, "score": s} for i, s in hits[:k]]

queries = [
    {"tenant": "entropa", "query": ["class=missing_approval", "decision=accept", "severity=high"], "k": 3, "threshold": 400},
    {"tenant": "entropa", "query": ["class=missing_approval", "decision=accept", "severity=high"], "k": 3, "threshold": 0},
    {"tenant": "entropa", "query": P[0]["terms"], "k": 3, "threshold": 400},
    {"tenant": "bigironbank", "query": P[0]["terms"], "k": 3, "threshold": 0},
    {"tenant": "entropa", "query": ["class=cosmic_ray", "decision=accept"], "k": 3, "threshold": 400},
]
for q in queries:
    q["hits"] = search(q["tenant"], q["query"], q["k"], q["threshold"])

out = {
    "weights": WEIGHTS, "threshold": THRESHOLD,
    "precedents": P, "revoked": REVOKED,
    "index_hash": ih,
    "index_hash_other_threshold_0": index_hash(admitted, WEIGHTS, 0),
    "manifest_hash": manifest_hash([p["id"] for p in admitted], REVOKED),
    "memory": {"ids": ["p2", "p1"], "hash": memory_hash(ih, ["p2", "p1"])},
    "queries": queries,
}
p = pathlib.Path(__file__).resolve().parents[2] / "crates/council/tests/vectors/memory_v1.json"
p.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
print("wrote", p.name, [len(q["hits"]) for q in queries])
