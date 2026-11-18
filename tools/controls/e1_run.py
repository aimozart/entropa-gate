"""E1 runs: collect, write the evidence files, emit the receipt, write the evidence index (E1 task 2; tasks 3 and 4 add their own).

    python3 -m tools.controls.e1_run crypto-inventory     # live: one TLS handshake per host in compliance/crypto-targets.json (our own assets)

Outputs go to docs/evidence/e1/: the CBOM, and an index of what was found (no PEM, no keys). Receipts go to a local scratch node OUTSIDE the
repository (E1_NODE_DIR, default ~/.cache/build/e1-scratch-node), built from the binary at target/release/entropa-platinum.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import uuid
from pathlib import Path

from . import cbom, crypto_inventory as ci

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "evidence" / "e1"
WORDING = "evidence mapped to the control; an inventory of observed TLS handshakes of our own hosts, not an assessment"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _suffix(out_dir: Path, date: str) -> str:
    """'' for the first run of a day, '-r2', '-r3', ... after that: an earlier run is a dated record and is never overwritten."""
    n = 1
    while True:
        sfx = "" if n == 1 else f"-r{n}"
        if not (out_dir / f"cbom-{date}{sfx}.cdx.json").exists() and not (out_dir / f"crypto-inventory-{date}{sfx}.json").exists():
            return sfx
        n += 1


def _facts_and_findings(answered: list[dict]) -> tuple[dict, dict, list[str]]:
    by_cert: dict[str, list[str]] = {}
    for r in answered:
        if r.get("leaf_sha256"):
            by_cert.setdefault(r["leaf_sha256"], []).append(r["host"])
    shared = [dict(leaf_sha256=k, hosts=v) for k, v in by_cert.items() if len(v) > 1]
    keys: dict[str, int] = {}
    for r in answered:
        if r.get("chain"):
            keys[r["chain"][0]["public_key"]] = keys.get(r["chain"][0]["public_key"], 0) + 1
    n = len(answered)
    tls13 = sum(r["tls_version"] == "TLSv1.3" for r in answered)
    hyb = sum(bool(r.get("hybrid_pq_kex")) for r in answered)
    pq = sum(bool(r.get("leaf_pq_signature")) for r in answered)
    summary = dict(hosts_answered=n, hosts_tls13=tls13, hosts_hybrid_kex=hyb, hosts_pq_certificate_signature=pq, certificate_key_types=keys)
    findings = [
        f"{hyb} of {n} answering hosts negotiated a hybrid ML-KEM key exchange with an OpenSSL 3.5 client. It is supplied by the hosting platforms "
        "(per the operator: Firebase Hosting and the Cloud Run front ends), not implemented by Entropa, and another client may negotiate differently.",
        ("The certificates are classical (" + "; ".join(f"{k} x{v}" for k, v in sorted(keys.items())) + "): no post-quantum signature protects the certificates."
         if pq == 0 else f"{pq} of {n} hosts present a post-quantum certificate signature; the rest are classical."),
        "Crypto-agility: this inventory exists; a documented plan for changing certificate algorithms is not yet written (known gap crypto_agility_plan_missing "
        "in compliance/controls-rubric.json).",
    ]
    facts = dict(shared_leaf_certificates=shared, shared_certificate_reading="a fact about how the certificates are issued, not a gap")
    return facts, summary, findings


def run_crypto_inventory(targets, out_dir: Path, node, runner=None, x509=None, now: str | None = None, serial: str | None = None,
                         allow_test_port: bool = False) -> dict:
    ts = now or _now()
    date = ts[:10]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sfx = _suffix(out_dir, date)
    results = ci.collect(targets, runner=runner, x509=x509, now=ts, allow_test_port=allow_test_port)
    bom = cbom.build_cbom(results, ts, serial or f"urn:uuid:{uuid.uuid4()}")
    cb_name = f"cbom-{date}{sfx}.cdx.json"
    (out_dir / cb_name).write_bytes(cbom.to_bytes(bom))
    sha = cbom.sha256_hex(bom)
    answered = [r for r in results if r.get("answered")]
    receipt = None
    run_id = f"e1-crypto-inventory-{date}{sfx}"
    if node is not None:
        got = node.emit_crypto_inventory(cbom_sha256=sha, hosts_in_scope=len(results), hosts_answered=len(answered), run_id=run_id)
        receipt = dict(index=got["index"], subject_hash=got["subject_hash"], root=got["root"], size=got["size"], label="crypto_inventory",
                       control="pci_dss_12_3_3", run_id=run_id)
    hosts = []
    for r in answered:
        leaf = r["chain"][0] if r.get("chain") else None
        hosts.append(dict(name=r["name"], host=r["host"], port=r["port"], tls_version=r["tls_version"], cipher_suite=r["cipher_suite"], group=r.get("group"),
                          group_source=r.get("group_source"), hybrid_pq_kex=r["hybrid_pq_kex"], peer_signature_type=r.get("peer_signature_type"),
                          verification=r.get("verification"), verify_return_code=r.get("verify_return_code"), hostname_in_san=r.get("hostname_in_san"),
                          san=r.get("san"), leaf=leaf, leaf_sha256=r.get("leaf_sha256"), leaf_pq_signature=r.get("leaf_pq_signature"),
                          leaf_days_to_expiry=r.get("leaf_days_to_expiry")))
    facts, summary, findings = _facts_and_findings(answered)
    index = dict(evidence_kind="crypto_inventory", generated=ts, run_id=run_id, wording=WORDING, facts=facts, summary=summary, findings=findings, cbom_file=cb_name, cbom_sha256=sha, hosts_in_scope=len(results),
                 hosts_answered=len(answered), not_answered=[dict(host=r["host"], error=r.get("error")) for r in results if not r.get("answered")],
                 hosts=hosts, receipt=receipt)
    (out_dir / f"crypto-inventory-{date}{sfx}.json").write_text(json.dumps(index, indent=1, sort_keys=True) + "\n")
    return dict(cbom_sha256=sha, hosts_in_scope=len(results), hosts_answered=len(answered), receipt=receipt, files=[cb_name, f"crypto-inventory-{date}{sfx}.json"])


def run_log_integrity(out_dir: Path, work_dir: Path, node, binary: Path, now: str | None = None, records: int = 5) -> dict:
    """The tamper demonstration on a dedicated demo node (work_dir, outside the evidence directory), two receipts, and the evidence file."""
    from . import log_integrity as li
    ts = now or _now()
    res = li.run_demo(binary, work_dir, records=records)
    got = li.emit_receipts(node, res, run_id=f"e1-log-integrity-{ts[:10]}-{ts[11:13]}{ts[14:16]}") if node is not None else []
    path = li.write_evidence(res, out_dir, ts, got)
    return dict(file=path.name, receipts=got, original_verify=res["original_verify_before"], copy_failed=not res["copy_verify"]["ok"])


def default_node():
    from .receipts import Node
    d = Path(os.environ.get("E1_NODE_DIR") or Path.home() / ".cache" / "build" / "e1-scratch-node")
    n = Node(d, Path(os.environ.get("E1_PLATINUM_BIN") or ROOT / "target" / "release" / "entropa-platinum"))
    n.init()
    return n


def main(argv: list[str]) -> int:
    if argv[:1] == ["crypto-inventory"]:
        targets = ci.load_targets(ROOT / "compliance" / "crypto-targets.json")
        r = run_crypto_inventory(targets, OUT, default_node())
        print(json.dumps(r, indent=1, sort_keys=True))
        return 0
    if argv[:1] == ["log-integrity"]:
        stamp = _now().replace(":", "").replace("-", "")
        work = Path.home() / ".cache" / "build" / f"e1-tamper-demo-{stamp}"          # outside the repo; holds a throwaway demo key
        binary = Path(os.environ.get("E1_PLATINUM_BIN") or ROOT / "target" / "release" / "entropa-platinum")
        r = run_log_integrity(OUT, work, default_node(), binary)
        print(json.dumps(r, indent=1, sort_keys=True))
        return 0
    print("usage: python3 -m tools.controls.e1_run crypto-inventory | log-integrity", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
