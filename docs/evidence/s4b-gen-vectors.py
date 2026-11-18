# Independent generator for crates/policy/tests/vectors/policy_decision_v1.json (json + blake3).
import json, blake3
A = "0123456789abcdef"; P = "fedcba9876543210"
SH = blake3.blake3(b"subject-1").hexdigest()
PH = blake3.blake3(b"policy-set-1").hexdigest()
TS = 1700000000
def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def digest(c):
    b = c.encode()
    return blake3.blake3(b"entropa-policy-decision-v1\x00" + len(b).to_bytes(4, "big") + b).hexdigest()
def rec(**kw):
    o = {"v": 1, "type": "policy.decision", "actor": A, "ts": TS, "principal": P, "subject_hash": SH, "policy_set_hash": PH}
    o.update(kw); return o
cases = []
def add(name, params, obj):
    c = canon(obj); cases.append({"name": name, "params": params, "canonical": c, "digest_hex": digest(c)})
add("allow_delete", {"action": "delete", "cedar": "allow", "determining": ["humans-with-approval-do-hard-rule-actions"], "error_policies": [], "approval_state": "approved", "approval_attested": False, "outcome": "allow", "reason": "allowed", "enforced": True},
    rec(action="delete", cedar="allow", determining=["humans-with-approval-do-hard-rule-actions"], errors=[], approval_state="approved", approval_attested=False, final="allow", reason="allowed", enforced=True))
add("deny_deploy_pending", {"action": "deploy", "cedar": "deny", "determining": [], "error_policies": [], "approval_state": "pending", "approval_attested": False, "outcome": "deny", "reason": "gate_pending", "enforced": False},
    rec(action="deploy", cedar="deny", determining=[], errors=[], approval_state="pending", approval_attested=False, final="deny", reason="gate_pending", enforced=False))
print(json.dumps({"format": "entropa policy decision records v1 (docs/ARCHITECTURE-CEDAR.md section 7)", "generated_by": "independent Python script (json + blake3), not by the Rust code",
  "fixed": {"actor": A, "principal": P, "subject_hash": SH, "policy_set_hash": PH, "ts": TS}, "cases": cases}, indent=1))
