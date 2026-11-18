"""Machine check of a register quote against its local source text (E1 task 1). Standard library plus the system `pdftotext`.

A quote counts as verbatim when it is found in the source after BOTH sides are reduced the same way: Unicode NFKC, soft hyphens removed,
typographic quotes and dashes made plain, and ALL whitespace and hyphens dropped (so a line-break hyphenation or a different space does not
matter; a different word, number or letter case does). It must also sit under its clause: the nearest preceding occurrence of the row's
anchor must be within `window` characters, so a phrase repeated elsewhere in the standard cannot vouch for the wrong clause. For a NIST OSCAL
catalog the anchor is `oscal:<control id>` and the quote is searched only in that control's own statement text.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import subprocess
import unicodedata
from dataclasses import dataclass
from pathlib import Path

DEFAULT_WINDOW = 1500
_PLAIN = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-", "‑": "-", "−": "-"})


@dataclass(frozen=True)
class Result:
    ok: bool
    why: str
    missing: bool = False


def compact(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).replace("­", "").translate(_PLAIN)
    return re.sub(r"[\s\-]+", "", t)


def _oscal_prose(parts) -> list[str]:
    out = []
    for p in parts or []:
        if isinstance(p, dict):
            if isinstance(p.get("prose"), str):
                out.append(p["prose"])
            out.extend(_oscal_prose(p.get("parts")))
    return out


def _oscal_find(controls, cid):
    for c in controls or []:
        if c.get("id") == cid:
            return c
        hit = _oscal_find(c.get("controls"), cid)
        if hit is not None:
            return hit
    return None


def oscal_control_text(catalog: dict, cid: str) -> str | None:
    cat = catalog.get("catalog", {})
    ctl = _oscal_find(cat.get("controls"), cid)
    for g in cat.get("groups", []):
        ctl = ctl or _oscal_find(g.get("controls"), cid)
        if ctl is None:
            for sub in g.get("groups", []):
                ctl = ctl or _oscal_find(sub.get("controls"), cid)
    if ctl is None:
        return None
    return " ".join(_oscal_prose(ctl.get("parts")))          # the control's own statement, not its nested enhancements


def _html_text(raw: str) -> str:
    raw = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", raw)
    return html.unescape(re.sub(r"<[^>]+>", " ", raw))


def verify_entry(e: dict, dirs: list[Path], window: int = DEFAULT_WINDOW) -> Result:
    name = e["source_file"]
    path = next((Path(d) / name for d in dirs if (Path(d) / name).is_file()), None)
    if path is None:
        return Result(False, f"source file missing: {name}", missing=True)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != e["source_sha256"]:
        return Result(False, f"sha256 of {name} differs from the register")
    suffix = path.suffix.lower()
    anchor = e["anchor"]
    try:
        if suffix == ".pdf":
            text = subprocess.run(["pdftotext", str(path), "-"], capture_output=True, check=True).stdout.decode("utf-8", "replace")
        elif suffix in (".html", ".htm"):
            text = _html_text(raw.decode("utf-8", "replace"))
        elif suffix == ".json" and anchor.startswith("oscal:"):
            ctl = oscal_control_text(json.loads(raw), anchor.split(":", 1)[1])
            if ctl is None:
                return Result(False, f"anchor {anchor}: control not found in the catalog")
            return (Result(True, "found in the control's statement") if compact(e["quote"]) in compact(ctl)
                    else Result(False, f"quote not found in the statement of {anchor}"))
        else:
            text = raw.decode("utf-8", "replace")
    except (OSError, subprocess.CalledProcessError, ValueError) as ex:
        return Result(False, f"cannot read the source: {ex.__class__.__name__}")
    ct, cq, ca = compact(text), compact(e["quote"]), compact(anchor)
    spots = [m.start() for m in re.finditer(re.escape(cq), ct)]
    if not spots:
        return Result(False, "quote not found in the source")
    for i in spots:
        j = ct.rfind(ca, 0, i + 1)
        if j >= 0 and i - j <= window:
            return Result(True, "found under its anchor")
    return Result(False, f"quote found but not under its anchor {anchor!r} within {window} characters")
