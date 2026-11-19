"""INS2 slice 3: an INDEPENDENT derivation of what the gate writer's v2 checkpoints must contain, from the record bytes alone (own Merkle tree, own digest bytes, own chain digests).
Run: uv run --offline --with blake3 python3 docs/evidence/ins2/gen-gate-v2-expected.py LEDGER_DIR > crates/gate/tests/pins/gate_v2_expected.json
LEDGER_DIR holds records.log (hex lines) and checkpoints.log (JSON lines) of the pinned four-request scenario. Only the signature text of each line is read from the file (the signature is not derivable); everything else is computed here.
Spec (docs/THREAT-MODEL-OPERATOR.md section 5): digest = b"entropa-checkpoint-v2\\0" || be64(counter) || prev(32) || root(32) || be64(size) || be64(timestamp);
prev = 32 zero bytes for the first v2 checkpoint, else blake3(b"entropa-checkpoint-chain-v2\\0" || digest_of_previous || signature_hex_text_of_previous); the time of checkpoint i is max(event time i, time of i-1)."""
import json, struct, sys
from blake3 import blake3

d = sys.argv[1]
records = [bytes.fromhex(l.strip()) for l in open(d + "/records.log") if l.strip()]
lines = [json.loads(l) for l in open(d + "/checkpoints.log") if l.strip()]

def leaf(b): return blake3(b"\x00" + b).digest()
def node(l, r): return blake3(b"\x01" + l + r).digest()
def mth(leaves):
    n = len(leaves)
    if n == 1: return leaves[0]
    k = 1
    while k * 2 < n: k *= 2
    return node(mth(leaves[:k]), mth(leaves[k:]))

leaves = [leaf(r) for r in records]
out, prev, last_time = [], bytes(32), 0
for i, line in enumerate(lines):
    size = i + 1
    root = mth(leaves[:size])
    ts = line["timestamp"]  # the event times of the scenario increase, so max(event, previous) is the event time; asserted below
    assert ts >= last_time, "event times of the scenario must not decrease"
    digest = b"entropa-checkpoint-v2\x00" + struct.pack(">Q", i + 1) + prev + root + struct.pack(">Q", size) + struct.pack(">Q", ts)
    out.append({"counter": i + 1, "prev": prev.hex(), "root": root.hex(), "size": size, "timestamp": ts, "digest": digest.hex()})
    prev = blake3(b"entropa-checkpoint-chain-v2\x00" + digest + line["signature"].encode()).digest()
    last_time = ts
print(json.dumps({"scenario": "four pinned requests, gate writer, seed 0x07 x32", "checkpoints": out}, indent=1))
