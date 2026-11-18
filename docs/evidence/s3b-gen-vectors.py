# Independent generator for crates/approvals/tests/vectors/approval_v1.json (struct/json + blake3).
import json, blake3
A, B, C = "0123456789abcdef", "fedcba9876543210", "00ff00ff00ff00ff"
SH = blake3.blake3(b"subject-1").hexdigest()
BH = blake3.blake3(b"chat-ref-1").hexdigest()
TS = 1700000000
def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def digest(c):
    b = c.encode()
    return blake3.blake3(b"entropa-approval-v1\x00" + len(b).to_bytes(4, "big") + b).hexdigest()
rid = blake3.blake3(b"entropa-approval-request-id-v1\x00" + A.encode() + b"\x00delete\x00" + SH.encode() + b"\x00" + str(TS).encode()).hexdigest()
cases = []
def add(kind, params, obj):
    c = canon(obj); cases.append({"kind": kind, "params": params, "canonical": c, "digest_hex": digest(c)})
add("request", {"actor": A, "ts": TS, "action_class": "delete", "subject_hash": SH, "subject_ref": "stage:S3b", "valid_for_secs": 86400},
    {"v": 1, "type": "request", "request_id": rid, "actor": A, "ts": TS, "action_class": "delete", "subject_hash": SH, "subject_ref": "stage:S3b", "valid_for_secs": 86400})
add("approve", {"actor": B, "ts": TS + 100, "request_id": rid, "on_behalf_of": C, "basis_hash": BH},
    {"v": 1, "type": "approve", "request_id": rid, "actor": B, "ts": TS + 100, "on_behalf_of": C, "basis_hash": BH})
add("approve", {"actor": B, "ts": TS + 100, "request_id": rid, "on_behalf_of": None, "basis_hash": None},
    {"v": 1, "type": "approve", "request_id": rid, "actor": B, "ts": TS + 100})
add("deny", {"actor": B, "ts": TS + 200, "request_id": rid, "reason": "too_risky", "on_behalf_of": None, "basis_hash": None},
    {"v": 1, "type": "deny", "request_id": rid, "actor": B, "ts": TS + 200, "reason_code": "too_risky"})
add("consume", {"actor": A, "ts": TS + 300, "request_id": rid},
    {"v": 1, "type": "consume", "request_id": rid, "actor": A, "ts": TS + 300})
print(json.dumps({"format": "entropa approval events v1 (docs/ARCHITECTURE-APPROVALS.md sections 3 and 4)", "generated_by": "independent Python script (json + blake3), not by the Rust code", "request_id": rid, "cases": cases}, indent=1))
