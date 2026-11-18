"""Log-integrity demonstration (E1 task 3).

A dedicated DEMO node is built with its own throwaway key (never a production ledger and never the E1 scratch node). It is copied, ONE byte of the
copy is changed, and offline verification (`entropa-platinum verify-evidence`) must fail on the copy and still pass on the original. Extra
positions, an appended byte and a truncated byte are measured and reported whatever the outcome. Measured facts about the demo node (two ledgers,
one key, no witness) are kept apart from facts that are only STATED (the production estate), and nothing here reads or prints key material.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from .receipts import Node, ReceiptError

MARKER = ".e1-demo-copy"
LEDGER = "evidence-ledger"
WORDING = "evidence mapped to the control; a demonstration on a dedicated demo node, not a statement about any production ledger"


class NotADemoCopy(RuntimeError):
    pass


class DemoFailed(RuntimeError):
    pass


def tree_sha256(d: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(x for x in Path(d).rglob("*") if x.is_file() and x.name != "platinum.key"):
        h.update(str(p.relative_to(d)).encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def _target(d: Path) -> Path:
    files = [p for p in (Path(d) / LEDGER).rglob("*") if p.is_file()]
    if not files:
        raise DemoFailed("no ledger file to change")
    return max(files, key=lambda p: (p.stat().st_size, str(p)))


def tamper_copy(copy_dir: Path, kind: str = "flip", offset: int | None = None) -> dict:
    """Change the evidence ledger of a DEMO COPY. Refuses any directory that does not carry the demo-copy marker."""
    d = Path(copy_dir)
    if not (d / MARKER).is_file():
        raise NotADemoCopy(f"{d.name}: not a demo copy (no marker); nothing was changed")
    f = _target(d)
    data = bytearray(f.read_bytes())
    rel = str(f.relative_to(d))
    if kind == "flip":
        off = len(data) // 2 if offset is None else offset
        old = data[off]
        data[off] = old ^ 0x01
        f.write_bytes(bytes(data))
        return dict(kind="flip", file=rel, offset=off, old_byte=f"{old:02x}", new_byte=f"{data[off]:02x}")
    if kind == "append_byte":
        f.write_bytes(bytes(data) + b"\x00")
        return dict(kind=kind, file=rel, offset=len(data), old_byte=None, new_byte="00")
    if kind == "truncate_last_byte":
        f.write_bytes(bytes(data[:-1]))
        return dict(kind=kind, file=rel, offset=len(data) - 1, old_byte=f"{data[-1]:02x}", new_byte=None)
    raise ValueError(kind)


def _verify(node: Node) -> tuple[bool, str]:
    try:
        return True, node.verify()
    except ReceiptError as e:
        return False, str(e)[:240]


def _copy(src: Path, dst: Path, binary: Path) -> Node:
    shutil.copytree(src, dst)
    (dst / MARKER).write_text("a copy made by the E1 log-integrity demo; safe to change\n")
    return Node(dst, binary)


def _key_id(export: dict) -> str | None:
    rec = (export.get("records") or [None])[0]
    m = re.search(r'"key_id":"([0-9a-f]{16})"', bytes.fromhex(rec["record_hex"]).decode("utf-8", "replace")) if rec else None
    return m.group(1) if m else None


def run_demo(binary: Path, workdir: Path, records: int = 5) -> dict:
    work = Path(workdir)
    work.mkdir(parents=True, exist_ok=True)
    orig = Node(work / "original", binary)
    orig.init()
    for i in range(records):
        orig.emit(kind="evidence.control_check", label="log_integrity_check", decision="allow", reason="check_passed", control="nist_800_53_au_9",
                  total=1, passed=1, flagged=0, detail=f"demo-record-{i}", run_id=f"e1-demo-{i}")
    orig.log_decision(dict(label="ml_score", decision="info", reason="none", input="sha256:" + "a" * 8, output="demo", run_id="e1-demo-decision",
                           provider="fake", model_id="demo-model", input_tokens=0, output_tokens=0, cost_micro_usd=0))
    ok0, before = _verify(orig)
    if not ok0:
        raise DemoFailed("the demo original does not verify: " + before)
    tree_before = tree_sha256(orig.dir)
    ex, dec = orig.export(), orig.export_decisions()
    facts_measured = dict(
        ledger_directories=sorted(p.name for p in orig.dir.iterdir() if p.is_dir()),
        signing_key_files=sorted(p.name for p in orig.dir.iterdir() if p.is_file() and p.suffix == ".key"),
        same_key_id_across_both_ledgers=bool(_key_id(ex)) and _key_id(ex) == _key_id(dec),
        witnesses=ex.get("witnesses", []), signature_algorithm=ex.get("algorithm"),
        separate_storage_demonstrated=False,
        note="both ledgers, the key and the copies sit in one directory tree on one disk: separate storage is NOT demonstrated by this demo")
    # the main demonstration
    copy = _copy(orig.dir, work / "copy", binary)
    t = tamper_copy(copy.dir)
    a, b = (orig.dir / t["file"]).read_bytes(), (copy.dir / t["file"]).read_bytes()
    tamper = dict(file=t["file"], offset=t["offset"], old_byte=t["old_byte"], new_byte=t["new_byte"], size_equal=len(a) == len(b),
                  differing_bytes=sum(x != y for x, y in zip(a, b)))
    ok_c, msg_c = _verify(copy)
    # more positions, each on a fresh copy
    size = len(a)
    positions = []
    for k, (kind, off) in enumerate([("flip", 0), ("flip", size // 2), ("flip", size - 1), ("append_byte", None), ("truncate_last_byte", None)]):
        v = _copy(orig.dir, work / f"variant-{k}", binary)
        tt = tamper_copy(v.dir, kind=kind, offset=off)
        ok_v, msg_v = _verify(v)
        positions.append(dict(kind=kind, offset=tt["offset"], detected=(not ok_v) or msg_v != before, verify_message=msg_v))
    ok1, after = _verify(orig)
    stated = [
        dict(statement="three ledgers share one signing key", source="E1 order (the reviewer), 2026-11-13", measured=False),
        dict(statement="only the AI ledger is witnessed", source="E1 order (the reviewer), 2026-11-13", measured=False),
        dict(statement="a witness is an independent party, one witness is one trust anchor, and a witness only constrains the history it was shown",
             source="docs/ARCHITECTURE-WITNESS.md section 1", measured=False)]
    return dict(records=records, original_verify_before=before, original_verify_after=after if ok1 else "FAILED: " + after,
                original_tree_sha256_before=tree_before, original_tree_sha256_after=tree_sha256(orig.dir),
                copy_verify=dict(ok=ok_c, message=msg_c), tamper=tamper, positions=positions,
                facts=dict(measured_on_the_demo_node=facts_measured, stated_not_measured_by_this_demo=stated))


def _expect(res: dict) -> int:
    m = re.match(r"OK records=(\d+) checkpoints=(\d+)$", str(res.get("original_verify_before", "")))
    if (not m or res.get("original_verify_after") != res["original_verify_before"] or res.get("copy_verify", {}).get("ok") is not False
            or res.get("tamper", {}).get("differing_bytes") != 1):
        raise DemoFailed("the demonstration did not behave as expected; no receipt is emitted")
    return int(m.group(1))


def emit_receipts(node: Node, res: dict, run_id: str) -> list[dict]:
    """Two receipts: the original verified from start to end, and the one-byte-changed copy failed verification."""
    n = _expect(res)
    t = res["tamper"]
    a = node.emit(kind="evidence.control_check", label="log_integrity_check", decision="allow", reason="check_passed", control="nist_800_53_au_9",
                  total=n, passed=n, flagged=0, detail=f"original_verify=OK|records={n}|tree_sha256={res['original_tree_sha256_after']}", run_id=f"{run_id}-original")
    b = node.emit(kind="evidence.control_check", label="log_integrity_check", decision="deny", reason="check_failed", control="nist_800_53_au_9",
                  total=1, passed=0, flagged=1, detail=f"tampered_copy=FAIL|differing_bytes=1|file={t['file']}|offset={t['offset']}|original_after=OK", run_id=f"{run_id}-tampered-copy")
    for g, kind, label in ((a, "original_verified", "log_integrity_check"), (b, "tampered_copy_failed", "log_integrity_check")):
        g.update(what=kind, label=label, control="nist_800_53_au_9")
    return [a, b]


def write_evidence(res: dict, out_dir: Path, ts: str, receipts_list: list[dict]) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    date, n = ts[:10], 1
    while (out / f"log-integrity-{date}{'' if n == 1 else f'-r{n}'}.json").exists():
        n += 1
    path = out / f"log-integrity-{date}{'' if n == 1 else f'-r{n}'}.json"
    doc = dict(evidence_kind="log_tamper_detection", generated=ts, wording=WORDING, result=res, receipts=receipts_list)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return path
