# Independent generator for crates/witness/tests/vectors/witness_statement_v1.json (json + blake3), not the Rust code.
import json, blake3
def h(w): return blake3.blake3(w.encode()).hexdigest()
ZERO = "0" * 64
WPK = "ab" * 32
def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def digest(c):
    b = c.encode()
    return blake3.blake3(b"entropa-witness-statement-v1\x00" + len(b).to_bytes(4, "big") + b).hexdigest()
def stmt(**kw):
    o = {"v": 1, "type": "witness.cosign", "witness_pubkey": WPK}
    o.update(kw); return o
cases = []
def add(name, **kw):
    f = {k: kw[k] for k in ("log_id", "size", "root", "log_timestamp", "witness_time", "previous_size", "previous_root")}
    f["witness_pubkey"] = WPK
    c = canon(stmt(**kw)); cases.append({"name": name, "fields": f, "canonical": c, "digest_hex": digest(c)})
L = h("log-1")
add("first_checkpoint", log_id=L, size=3, root=h("root-3"), log_timestamp=1699999000, witness_time=1700000000, previous_size=0, previous_root=ZERO)
add("extension", log_id=L, size=7, root=h("root-7"), log_timestamp=1699999010, witness_time=1700000005, previous_size=3, previous_root=h("root-3"))
add("same_checkpoint_again", log_id=L, size=7, root=h("root-7"), log_timestamp=1699999010, witness_time=1700000006, previous_size=7, previous_root=h("root-7"))
add("empty_log_first", log_id=L, size=0, root=h("empty"), log_timestamp=1, witness_time=2, previous_size=0, previous_root=ZERO)
add("largest_numbers", log_id=h("log-2"), size=2**53 - 1, root=h("root-big"), log_timestamp=2**53 - 1, witness_time=2**53 - 1, previous_size=2**53 - 2, previous_root=h("root-prev"))
print(json.dumps({"format": "entropa witness statements v1 (docs/ARCHITECTURE-WITNESS.md section 2)", "generated_by": "independent Python script (json + blake3), not by the Rust code",
  "fixed": {"type": "witness.cosign", "v": 1, "witness_pubkey": WPK, "no_previous_root": ZERO}, "cases": cases}, indent=1))
