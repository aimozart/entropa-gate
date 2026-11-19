"""A local scratch Entropa node for E1 receipts (E1 tasks 2 to 4). Drives the entropa-platinum binary built from this branch.

The node directory holds a private signing key, so it lives OUTSIDE the repository (default ~/.cache/build/e1-scratch-node) and is never
committed. Receipts carry only closed codes, counts and a hash (the detail text is hashed by the node and dropped).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


class ReceiptError(RuntimeError):
    pass


class Node:
    def __init__(self, directory: Path, binary: Path):
        self.dir, self.bin = Path(directory), Path(binary)

    def _run(self, *args: str, stdin: str | None = None) -> str:
        p = subprocess.run([str(self.bin), *args, str(self.dir)], input=(stdin or "").encode(), capture_output=True, timeout=120)
        if p.returncode != 0:
            raise ReceiptError(f"{args[0]} failed: {p.stderr.decode('utf-8', 'replace').strip()[:300]}")
        return p.stdout.decode("utf-8", "replace")

    def init(self) -> None:
        # a node is initialised when it has the legacy shared key or any per-ledger key (KEYS1)
        if not any((self.dir / f).exists() for f in ("platinum.key", "decisions.key", "evidence.key", "council.key")):
            self._run("init")

    def emit(self, *, kind: str, label: str, decision: str, reason: str, control: str, total: int, passed: int, flagged: int, detail: str, run_id: str) -> dict:
        body = json.dumps(dict(kind=kind, label=label, decision=decision, reason=reason, control=control, total=total, passed=passed,
                               flagged=flagged, detail=detail, run_id=run_id))
        return json.loads(self._run("log-evidence", stdin=body))

    def verify(self) -> str:
        return self._run("verify-evidence").strip().splitlines()[-1]

    def export(self) -> dict:
        return json.loads(self._run("export-evidence"))

    def export_decisions(self) -> dict:
        return json.loads(self._run("export-decisions"))

    def verify_ai(self) -> str:
        """Verify the AI-decision ledger (the node's other ledger)."""
        return self._run("verify").strip().splitlines()[-1]

    def log_decision(self, payload: dict) -> dict:
        return json.loads(self._run("log", stdin=json.dumps(payload)))

    def emit_crypto_inventory(self, *, cbom_sha256: str, hosts_in_scope: int, hosts_answered: int, run_id: str) -> dict:
        flagged = hosts_in_scope - hosts_answered
        ok = flagged == 0
        return self.emit(kind="evidence.control_check", label="crypto_inventory", decision="allow" if ok else "deny",
                         reason="check_passed" if ok else "check_failed", control="pci_dss_12_3_3", total=hosts_in_scope, passed=hosts_answered,
                         flagged=flagged, detail=f"cbom_sha256={cbom_sha256}|hosts={hosts_in_scope}|answered={hosts_answered}", run_id=run_id)
