#!/usr/bin/env python3
"""Independent generator of the S12b golden vectors (no Rust involved).
S12c: every event carries a signed `alg` label (algorithm agility, G1 item 9).
Run: uv run --offline --with blake3 python3 docs/evidence/s12b-gen-vectors.py
Writes crates/council/tests/vectors/council_v1.json. Definitions (docs/ARCHITECTURE-COUNCIL.md sections 6, 12):
  canonical bytes  = JSON with keys sorted at every level, separators (',', ':'), no 'sig'
  event digest     = BLAKE3("entropa-council-v1" 0x00 || u32be(len(canonical)) || canonical)
  window hash      = BLAKE3("entropa-council-window-v1" 0x00 || for each ref in sorted byte order: u32be(len) || ref)
  findings hash    = BLAKE3("entropa-council-findings-v1" 0x00 || the same over finding ids)
  replay input hash= BLAKE3("entropa-council-replay-input-v1" 0x00 || u32be(len) || input)
  index hash       = BLAKE3("entropa-council-index-v1" 0x00 || u32be(len(id)) id || u32be(dim) || u32be(len(norm)) norm
                            || u32be(n) || for each entry sorted by id: u32be(len(id)) id || each component as f32 little-endian)"""
import json, pathlib, struct
from blake3 import blake3

def canon(x): return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def u32(n): return struct.pack(">I", n)
def digest(c): return blake3(b"entropa-council-v1\x00" + u32(len(c)) + c).hexdigest()
def hashed(domain, items):
    h = blake3(domain + b"\x00")
    for s in sorted(i.encode() for i in items): h.update(u32(len(s)) + s)
    return h.hexdigest()

SID = "a" * 64
H = lambda c: c * 64
cases = [
 {"name": "session.opened", "event": {"v": 1, "type": "session.opened", "alg": "ML-DSA-65", "session_id": SID, "actor": "0123456789abcdef", "ts": 1800000000,
   "cadence": "weekly", "trigger": "schedule", "period_start": 1799000000, "period_end": 1799600000, "window_hash": H("b"),
   "n_decisions": 4, "expires": 1800604800}},
 {"name": "finding.submitted", "event": {"v": 1, "type": "finding.submitted", "alg": "ML-DSA-65", "session_id": SID, "actor": "0123456789abcdef", "ts": 1800000100,
   "finding_id": "f-1", "subject_ref": "idx:1", "class": "missing_approval", "severity": "high", "confidence": "medium",
   "proposed_change": "test", "evidence": [{"kind": "ledger_index", "ref": "idx:1"}, {"kind": "event_hash", "ref": H("c")}],
   "provider": "vertex", "model_id": "gemini-flash", "text_hash": None}},
 {"name": "decision.recorded", "event": {"v": 1, "type": "decision.recorded", "alg": "ML-DSA-65", "session_id": SID, "actor": "fedcba9876543210", "ts": 1800000900,
   "finding_id": "f-1", "decision": "accept", "reason": "evidence_sufficient", "change_kind": "test", "approval_ref": "appr-1",
   "attested": False, "auth_ref": H("d")}},
]
for c in cases:
    cb = canon(c["event"]).encode()
    c["canonical"] = cb.decode(); c["digest"] = digest(cb)

entries = {"p2": [0.0, 1.0, 0.0], "p1": [1.0, 0.0, 0.0], "p3": [0.5, 0.5, 0.0]}
h = blake3(b"entropa-council-index-v1\x00")
mid, dim, norm = b"test-embed", 3, b"unit"
h.update(u32(len(mid)) + mid + u32(dim) + u32(len(norm)) + norm + u32(len(entries)))
for i in sorted(entries):
    h.update(u32(len(i.encode())) + i.encode() + b"".join(struct.pack("<f", x) for x in entries[i]))
out = {
  "cases": cases,
  "window": {"refs": ["idx:7", "idx:3", "idx:12"], "hash": hashed(b"entropa-council-window-v1", ["idx:7", "idx:3", "idx:12"])},
  "findings": {"ids": ["f-2", "f-1", "f-10"], "hash": hashed(b"entropa-council-findings-v1", ["f-2", "f-1", "f-10"])},
  "replay_input": {"input": "principal=agent-entropa;action=read;resource=log", "hash": blake3(b"entropa-council-replay-input-v1\x00" + u32(len(b"principal=agent-entropa;action=read;resource=log")) + b"principal=agent-entropa;action=read;resource=log").hexdigest()},
  "index": {"model": {"id": "test-embed", "dim": 3, "normalization": "unit"}, "entries": entries, "hash": h.hexdigest()},
}
p = pathlib.Path(__file__).resolve().parents[2] / "crates/council/tests/vectors/council_v1.json"
p.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
print("wrote", p.name, len(cases), "event cases")
