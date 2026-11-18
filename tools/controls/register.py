"""The control register (compliance/controls-register.json): load and check it (E1 task 1)."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

KEYS = ("id", "standard", "version", "clause", "quote", "anchor", "source_file", "source_sha256", "source_kind", "evidence_type")
KINDS = ("primary", "secondary")
# Clauses whose text sits far below their heading (a long article) need a wider anchor window; everything else uses the default.
WINDOWS = {"EUAIA-26-6": 20000}


class RegisterError(ValueError):
    pass


def check_rows(rows) -> list[dict]:
    if not isinstance(rows, list) or not rows:
        raise RegisterError("the register must be a non-empty list of rows")
    seen = set()
    for r in rows:
        if not isinstance(r, dict) or set(r) != set(KEYS):
            raise RegisterError(f"row must have exactly the keys {KEYS}: {r.get('id') if isinstance(r, dict) else r!r}")
        for k in KEYS:
            if not isinstance(r[k], str) or not r[k].strip():
                raise RegisterError(f"{r['id']}: {k} must be a non-empty string")
        if len(r["quote"].split()) > 25:
            raise RegisterError(f"{r['id']}: quote is longer than 25 words")
        if r["id"] in seen:
            raise RegisterError(f"duplicate id {r['id']}")
        seen.add(r["id"])
        if r["source_kind"] not in KINDS:
            raise RegisterError(f"{r['id']}: source_kind must be one of {KINDS}")
        if not re.fullmatch(r"[0-9a-f]{64}", r["source_sha256"]):
            raise RegisterError(f"{r['id']}: source_sha256 must be a sha256 hex digest")
    return rows


def load_register(path: Path) -> list[dict]:
    try:
        d = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise RegisterError(f"cannot read the register: {e.__class__.__name__}") from None
    if not isinstance(d, dict):
        raise RegisterError("the register must be an object with a 'rows' list")
    return check_rows(d.get("rows"))


def source_dirs() -> list[Path]:
    """Where the source files live: the licensed standards (outside this repo) and the stored public texts (outside both repos)."""
    return [Path(os.environ.get("E1_STANDARDS_DIR") or Path.home() / "a private repository" / "docs" / "standards"),
            Path(os.environ.get("E1_PUBLIC_SOURCES_DIR") or Path.home() / ".cache" / "build" / "controls-e1-sources")]


def window_for(row: dict) -> int:
    from .quotes import DEFAULT_WINDOW
    return WINDOWS.get(row["id"], DEFAULT_WINDOW)
