# Independent generator for crates/ledger/tests/vectors/ledger_event_v1.json (json + blake3), not the Rust code.
import json, blake3
def h(w): return blake3.blake3(w.encode()).hexdigest()
def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def digest(c):
    b = c.encode()
    return blake3.blake3(b"entropa-explorer-event-v1\x00" + len(b).to_bytes(4, "big") + b).hexdigest()
KEY = "0123456789abcdef"
def base(**kw):
    o = {"v": 1, "type": "explorer.event", "synthetic": True, "key_id": KEY, "ts": 1700000000, "approval_ref": None, "agent": None,
         "role": None, "attested_by": None, "pubkey_fingerprint": None}
    o.update(kw); return o
cases = []
def add(name, **kw):
    o = base(**kw)
    f = {k: o[k] for k in ("kind", "tenant", "key_id", "handle", "ts", "subject_hash", "label", "decision", "reason", "approval_ref", "agent", "role", "attested_by", "pubkey_fingerprint")}
    c = canon(o); cases.append({"name": name, "fields": f, "canonical": c, "digest_hex": digest(c)})
add("tx_screened_with_model", kind="tx.screened", tenant="bigironbank", handle="agent-bigironbank", subject_hash=h("tx-17"), label="fraud_screen", decision="hold", reason="needs_review",
    agent={"provider": "fake", "model_id": "amazon.nova-lite-v1:0", "input_tokens": 1200, "output_tokens": 150, "cost_micro_usd": 108})
add("audit_answer", kind="agent.invocation", tenant="entropa", handle="agent-entropa", ts=1700000060, subject_hash=h("q-3"), label="audit_question", decision="info", reason="cited_receipts", approval_ref=h("req-9"),
    agent={"provider": "bedrock", "model_id": "amazon.nova-lite-v1:0", "input_tokens": 3000, "output_tokens": 500, "cost_micro_usd": 300})
add("directory_entry", kind="directory.actor", tenant="entropa", handle="human-principal", ts=1699999000, subject_hash=h("dir-1"), label="actor_registered", decision="info", reason="none",
    role="human", attested_by="orchestrator-agent", pubkey_fingerprint="fedcba9876543210")
add("largest_numbers", kind="agent.invocation", tenant="hippagrchealthcare", handle="agent-hippagrchealthcare", ts=2**53 - 1, subject_hash=h("case-1"), label="case_review", decision="release", reason="within_limits",
    agent={"provider": "vertex", "model_id": "gemini-synthetic:1", "input_tokens": 2**53 - 1, "output_tokens": 0, "cost_micro_usd": 2**53 - 1})
print(json.dumps({"format": "entropa explorer events v1 (docs/ARCHITECTURE-EXPLORER.md section 4)", "generated_by": "independent Python script (json + blake3), not by the Rust code",
  "cases": cases}, indent=1))
