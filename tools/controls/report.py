"""E1 report generator: the control register joined to receipts, status by the rubric fixed BEFORE any result (compliance/controls-rubric.json).

Wording: evidence mapped to the control, never a claim that a standard is met. Receipts are CHECKED, not assumed: each one must appear in the
node's export with the right kind, label, control and subject hash, and the whole ledger must verify offline; otherwise the evidence kind it backs is
absent and the rows that need it fall back by the rubric. Known gaps come first in the report.

    python3 -m tools.controls.report      # writes docs/evidence/e1/controls-report.md and controls-report.json
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

from . import quotes as quotes_mod, register
from .receipts import Node, ReceiptError

STATUSES = ("MET BY EVIDENCE", "PARTIAL", "GAP")
ROOT = Path(__file__).resolve().parents[2]
RUBRIC_PATH = ROOT / "compliance" / "controls-rubric.json"
WORDING = "evidence mapped to the control; not an assessment of compliance, and not a claim that any standard is met"
LIMITS = [
    "The three HIPAA rows rest on a public mirror (Cornell LII) of 45 CFR 164.312, not on the official eCFR text, so the fixed rubric caps them at PARTIAL.",
    "Receipts come from a LOCAL scratch node whose signing key is a throwaway made for E1. They verify offline on that node. No live node and no witness is involved.",
    "The crypto inventory is one observation from one client (OpenSSL 3.5) at one network position on one day. The hybrid key exchange it shows is supplied by the hosting platforms, not by Entropa.",
    "The CBOM is checked structurally against the parts of CycloneDX 1.6 we emit; it is not validated with the official JSON Schema (no validator is installed).",
    "The log-integrity demonstration uses a dedicated demo node. No production ledger was copied or changed. Separate storage and key sharing in production are STATED, not measured.",
    "Evidence kinds E1 does not produce (policy documents, retention, key lifecycle, alerting, review records, distinct signing keys) are absent, so rows that need them cannot be MET.",
    "Register quotes are at most 25 words; a clause must be read in full in its source to be interpreted.",
    "Dated note (2026-11-13, added after review): after the 2026-11-13 inventory, hippagrchealthcare.site was retired (hosting site deleted, DNS kept) and "
    "bigironbank.online is being retired; the 2026-11-13 inventory is kept as the dated record of what existed then.",
    "This is revision 2 of the report: it adds the dated note above. Statuses, rubric and evidence are unchanged. Revision 1, the version outcome-E1 was "
    "bound to, is kept as controls-report-at-outcome.json and .md.",
]


class ReportError(ValueError):
    pass


def row_status(cid: str, rubric: dict, present: set, quote_ok: bool, source_kind: str) -> dict:
    ctl = rubric["controls"].get(cid)
    if ctl is None:
        raise ReportError(f"unknown control {cid!r}")
    required, gaps = list(ctl["required"]), list(ctl["gaps"])
    covered = [k for k in required if k in present]
    missing = [k for k in required if k not in present]
    if not covered:
        return dict(status="GAP", covered=[], missing=missing, gaps=gaps, why="no required evidence kind has a verifying receipt")
    reasons = []
    if missing:
        reasons.append("missing evidence: " + ", ".join(missing))
    if gaps:
        reasons.append("known gap attached: " + ", ".join(gaps))
    if source_kind != "primary":
        reasons.append("the source text is secondary")
    if not quote_ok:
        reasons.append("the quote was not verified against its source")
    if not reasons:
        return dict(status="MET BY EVIDENCE", covered=covered, missing=[], gaps=[], why="every required evidence kind has a verifying receipt, no known gap, primary source verified")
    return dict(status="PARTIAL", covered=covered, missing=missing, gaps=gaps, why="; ".join(reasons))


# ---- evidence: receipts are checked against the node ----
def _decode(rec: dict) -> dict:
    txt = bytes.fromhex(rec["record_hex"]).decode("utf-8", "replace")
    sh = re.search(r'"subject_hash":"([0-9a-f]{64})"', txt)
    ct = re.search(r'"control":"([a-z0-9_]+)"', txt)
    return dict(kind=rec["kind"], label=rec["label"], subject_hash=sh.group(1) if sh else None, control=ct.group(1) if ct else None)


def _check_receipt(rc: dict, records: dict, label: str, control: str) -> tuple[bool, str]:
    r = records.get(rc.get("index"))
    if r is None:
        return False, f"receipt index {rc.get('index')} is not in the node"
    if r["kind"] != "evidence.control_check" or r["label"] != label or r["control"] != control:
        return False, f"receipt index {rc.get('index')} has a different kind, label or control in the node"
    if r["subject_hash"] != rc.get("subject_hash"):
        return False, f"receipt index {rc.get('index')}: the subject hash does not match the node's record"
    return True, "ok"


def _load_json(p: Path):
    return json.loads(p.read_text())


def load_evidence(evidence_dir: Path, node, rubric: dict | None = None) -> dict:
    rubric = rubric or _load_json(RUBRIC_PATH)
    ev_dir = Path(evidence_dir)
    out = {k: dict(present=False, why="not produced by E1", receipts=[], files=[]) for k in rubric["evidence_kinds"]}
    out["separate_storage"]["why"] = ("recorded facts are documented or stated, not measured by the demonstration, so no receipt was emitted "
                                      "(the facts are in the log-integrity evidence file)")
    ledger_ok, ledger_msg, records, algorithm = False, "no node was given, so receipts cannot be verified", {}, None
    if node is not None:
        try:
            ledger_msg = node.verify()
            ledger_ok = True
            exp = node.export()
            algorithm = exp.get("algorithm")
            records = {r["index"]: _decode(r) for r in exp["records"]}
        except (ReceiptError, ValueError, KeyError) as e:
            ledger_msg = f"node ledger did not verify offline: {e}"
    fail = lambda why: dict(present=False, why=why, receipts=[], files=[])
    # crypto inventory: the latest run counts, earlier runs are dated records
    runs = []
    for p in sorted(ev_dir.glob("crypto-inventory-*.json")):
        d = _load_json(p)
        runs.append((d.get("generated", ""), p.name, d))
    if not runs:
        out["crypto_inventory"] = fail("no crypto inventory evidence file")
    else:
        runs.sort()
        _, name, d = runs[-1]
        dated = [n for _, n, _ in runs[:-1]]
        why = None
        cb = ev_dir / d.get("cbom_file", "")
        if not ledger_ok:
            why = ledger_msg if "did not verify" in ledger_msg else f"node ledger did not verify offline: {ledger_msg}"
        elif not cb.is_file() or hashlib.sha256(cb.read_bytes()).hexdigest() != d.get("cbom_sha256"):
            why = "the CBOM file's sha256 differs from the one in the index (or the file is missing)"
        elif not d.get("receipt"):
            why = "the latest inventory has no receipt"
        else:
            ok, w = _check_receipt(d["receipt"], records, "crypto_inventory", "pci_dss_12_3_3")
            if not ok:
                why = w
            elif d.get("hosts_answered", 0) < 1:
                why = "no host answered"
        out["crypto_inventory"] = dict(present=why is None, why=why or "the receipt verifies and the CBOM matches its hash", latest=name, dated_records=dated,
                                       files=[name, d.get("cbom_file")], receipts=[d["receipt"]] if d.get("receipt") else [],
                                       detail=dict(hosts_in_scope=d.get("hosts_in_scope"), hosts_answered=d.get("hosts_answered")))
    # log integrity
    logs = sorted(ev_dir.glob("log-integrity-*.json"), key=lambda p: (_load_json(p).get("generated", ""), p.name))
    if not logs:
        for k in ("log_tamper_detection", "signed_records"):
            out[k] = fail("no log-integrity evidence file")
    else:
        d = _load_json(logs[-1])
        res, rcs = d.get("result", {}), d.get("receipts", [])
        behaved = (re.match(r"OK records=\d+ checkpoints=\d+$", str(res.get("original_verify_before"))) is not None
                   and res.get("original_verify_after") == res.get("original_verify_before") and res.get("copy_verify", {}).get("ok") is False
                   and res.get("tamper", {}).get("differing_bytes") == 1
                   and res.get("original_tree_sha256_before") == res.get("original_tree_sha256_after"))
        by = {r.get("what"): r for r in rcs}
        why_t = why_s = None
        if not ledger_ok:
            why_t = why_s = ledger_msg if "did not verify" in ledger_msg else f"node ledger did not verify offline: {ledger_msg}"
        elif not behaved:
            why_t = why_s = "the demonstration did not behave as expected in its recorded result"
        else:
            for need in ("original_verified", "tampered_copy_failed"):
                if need not in by:
                    why_t = f"missing receipt {need}"
                else:
                    ok, w = _check_receipt(by[need], records, "log_integrity_check", "nist_800_53_au_9")
                    why_t = why_t or (None if ok else w)
            if "original_verified" not in by:
                why_s = "missing receipt original_verified"
            else:
                ok, w = _check_receipt(by["original_verified"], records, "log_integrity_check", "nist_800_53_au_9")
                why_s = None if ok else w
                if ok and algorithm != "ML-DSA-65":
                    why_s = f"the node signs with {algorithm}, not ML-DSA-65"
        files = [logs[-1].name]
        out["log_tamper_detection"] = dict(present=why_t is None, why=why_t or "a one-byte change to a copy fails offline verification; the original passes; both receipts verify",
                                           files=files, receipts=[by[k] for k in ("original_verified", "tampered_copy_failed") if k in by])
        out["signed_records"] = dict(present=why_s is None, why=why_s or "the original ledger verifies from start to end offline and the node signs with ML-DSA-65",
                                     files=files, receipts=[by["original_verified"]] if "original_verified" in by else [])
    return out


def verify_quotes(rows: list[dict]) -> dict:
    dirs = register.source_dirs()
    out = {}
    for r in rows:
        res = quotes_mod.verify_entry(r, dirs, window=register.window_for(r))
        out[r["id"]] = dict(ok=res.ok, why=res.why)
    return out


def build_report(rows: list[dict], rubric: dict, evidence: dict, quote_results: dict, generated: str, history: list, findings: list) -> dict:
    present = {k for k, v in evidence.items() if v["present"]}
    out_rows = []
    for r in rows:
        q = quote_results[r["id"]]
        s = row_status(r["id"], rubric, present, bool(q["ok"]), r["source_kind"])
        rc = sorted({x["index"] for k in s["covered"] for x in evidence[k].get("receipts", [])})
        row = dict(id=r["id"], standard=r["standard"], version=r["version"], clause=r["clause"], quote=r["quote"], source_kind=r["source_kind"],
                             source_file=r["source_file"], quote_verified=bool(q["ok"]), quote_note=q["why"], status=s["status"], covered=s["covered"],
                             missing=s["missing"], gaps=s["gaps"], receipts=rc, why=s["why"])
        if s["status"] == "MET BY EVIDENCE":
            row["caveat"] = "the mechanism was demonstrated on a demo node built by the same binary; no production ledger was examined"
        out_rows.append(row)
    counts = {s: sum(x["status"] == s for x in out_rows) for s in STATUSES}
    nq = sum(x["quote_verified"] for x in out_rows)
    prim = sum(x["quote_verified"] and x["source_kind"] == "primary" for x in out_rows)
    summary = dict(counts, quotes_verified=f"{nq}/{len(out_rows)}", primary_quotes_verified=prim, secondary_rows=sum(x["source_kind"] != "primary" for x in out_rows))
    ci = evidence.get("crypto_inventory", {}).get("detail") or {}
    gap_ids = [x["id"] for x in out_rows if x["status"] == "GAP"]
    met_ids = [x["id"] for x in out_rows if x["status"] == "MET BY EVIDENCE"]
    outcome = [
        dict(forecast="every quote verified against its source", measured=f"{nq} of {len(out_rows)} verified; {prim} primary, {summary['secondary_rows']} secondary rows"),
        dict(forecast="most rows PARTIAL, a few MET, at least 5 GAP", measured=f"{counts['PARTIAL']} PARTIAL, {counts['MET BY EVIDENCE']} MET ({', '.join(met_ids) or 'none'}), {counts['GAP']} GAP ({', '.join(gap_ids) or 'none'})"),
        dict(forecast="the CBOM covers every in-scope host", measured=(f"{ci.get('hosts_answered')} of {ci.get('hosts_in_scope')} in-scope targets answered (localhost has no TLS service)" if ci else "no inventory loaded")),
        dict(forecast="every MET row has an offline-verifying receipt", measured="each MET row's required evidence has a receipt that was checked against the node and verified offline"
             if met_ids else "no row is MET"),
    ]
    return dict(report_version=1, generated=generated, wording=WORDING,
                known_gaps=[dict(id=k, text=v["text"], affects=v["affects"]) for k, v in rubric["known_gaps"].items()],
                findings=list(findings), summary=summary, rows=out_rows,
                evidence={k: dict(present=v["present"], why=v["why"], files=[f for f in v.get("files", []) if f], receipts=[x.get("index") for x in v.get("receipts", [])],
                                  latest=v.get("latest"), dated_records=v.get("dated_records")) for k, v in evidence.items()},
                plan_vs_outcome=outcome, history=list(history), limits=list(LIMITS))


def to_markdown(r: dict) -> str:
    L = ["# E1 self-assessment of our own estate", "", f"Generated {r['generated']}. **{r['wording']}.**", ""]
    L += ["## Known gaps", "", "Stated up front, before any row:", ""]
    for g in r["known_gaps"]:
        aff = ", ".join(g["affects"]) if g["affects"] else "no register row"
        L.append(f"- **{g['id']}**: {g['text']} (affects: {aff})")
    L += ["", "## Findings", ""] + [f"- {f}" for f in r["findings"]]
    s = r["summary"]
    L += ["", "## Summary", "", f"- MET BY EVIDENCE: {s['MET BY EVIDENCE']}", f"- PARTIAL: {s['PARTIAL']}", f"- GAP: {s['GAP']}",
          f"- Quotes verified against their source: {s['quotes_verified']} ({s['primary_quotes_verified']} primary; {s['secondary_rows']} rows rest on a secondary source)", "",
          "## Control rows", "", "| ID | Standard | Clause | Status | Source | Quote verified | Covered | Missing | Known gaps | Receipts |", "|---|---|---|---|---|---|---|---|---|---|"]
    for x in r["rows"]:
        L.append(f"| {x['id']} | {x['standard']} | {x['clause']} | {x['status']} | {x['source_kind']} | {'yes' if x['quote_verified'] else 'NO'} | "
                 f"{', '.join(x['covered']) or '-'} | {', '.join(x['missing']) or '-'} | {', '.join(x['gaps']) or '-'} | {', '.join(map(str, x['receipts'])) or '-'} |")
    L += ["", "Why each row has its status:", ""]
    for x in r["rows"]:
        L.append(f"- {x['id']}: {x['why']}")
        if x.get("caveat"):
            L.append(f"  - Caveat: {x['caveat']}.")
    L += ["", "## Evidence", ""]
    for k, v in r["evidence"].items():
        L.append(f"- **{k}**: {'present' if v['present'] else 'absent'}; {v['why']}" + (f" (files: {', '.join(v['files'])}; receipts: {v['receipts']})" if v["files"] else ""))
        if v.get("dated_records"):
            L.append(f"  - earlier runs kept as dated records: {', '.join(v['dated_records'])}")
    L += ["", "## Plan versus outcome", "", "| Forecast | Measured |", "|---|---|"] + [f"| {o['forecast']} | {o['measured']} |" for o in r["plan_vs_outcome"]]
    L += ["", "## History of commit hashes that changed", ""] + ([f"- {h['what']}: {h['old']} became {h['new']} (messages reworded to add the repository's required 'Test change:' line; content identical)" for h in r["history"]] or ["- none"])
    L += ["", "## Limits", ""] + [f"- {x}" for x in r["limits"]]
    return "\n".join(L) + "\n"


def write(r: dict, out_dir: Path) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md, js = out / "controls-report.md", out / "controls-report.json"
    md.write_text(to_markdown(r))
    js.write_text(json.dumps(r, indent=1) + "\n")
    return md, js


def main(argv: list[str]) -> int:
    import datetime as dt
    rubric = _load_json(RUBRIC_PATH)
    rows = register.load_register(ROOT / "compliance" / "controls-register.json")
    node = Node(Path(os.environ.get("E1_NODE_DIR") or Path.home() / ".cache" / "build" / "e1-scratch-node"),
                Path(os.environ.get("E1_PLATINUM_BIN") or ROOT / "target" / "release" / "entropa-platinum"))
    ev_dir = ROOT / "docs" / "evidence" / "e1"
    evidence = load_evidence(ev_dir, node, rubric)
    findings = []
    ci_name = evidence["crypto_inventory"].get("latest")
    if ci_name:
        d = _load_json(ev_dir / ci_name)
        findings += d.get("findings", [])
        for sh in d.get("facts", {}).get("shared_leaf_certificates", []):
            findings.append(f"Fact (not a gap): {len(sh['hosts'])} hosts present one shared certificate: {', '.join(sh['hosts'])}.")
        expiries = [h["leaf_days_to_expiry"] for h in d.get("hosts", []) if h.get("leaf_days_to_expiry") is not None]
        if expiries:
            findings.append(f"Certificates expire in {min(expiries)} to {max(expiries)} days from the inventory date.")
    findings.append("Log integrity: a one-byte change anywhere in the evidence ledger of a copy was detected, most by a checkpoint mismatch; a flip of the very last byte hits the trailing newline and is caught as a format error ('file ends with a partial line'), not as a cryptographic mismatch.")
    history = [dict(what="E-LABELS-2 RED commit", old="23dcdca", new="e54ac07"), dict(what="E-LABELS-2 commit", old="05bf716", new="9b734fa")]
    r = build_report(rows, rubric, evidence, verify_quotes(rows), dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), history, findings)
    md, js = write(r, ev_dir)
    print(json.dumps(r["summary"], indent=1))
    print(md, js)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
