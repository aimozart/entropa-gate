"""R1 exit bar: no licensed text is in git. Windows of 12 consecutive words are taken from EVERY LICENSED clause of the sealed corpus (the PCI DSS text,
which lives only in the local sealed store) and none may appear in any tracked file of this repository. The detector is proved to bite with a planted
copy in a throwaway repository. Needs the sealed store (host side); FAILS when it is missing unless E1_ALLOW_MISSING_SOURCES=1."""
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
STORE = Path(os.environ.get("ENTROPA_STANDARDS_STORE") or Path.home() / ".cache" / "build" / "standards-store")
VERSION = "c2026-11-13"
WORDS = 12


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", t).strip()


def windows(text: str, n: int = WORDS, step: int = 6):
    w = norm(text).split(" ")
    return [" ".join(w[i:i + n]) for i in range(0, max(1, len(w) - n + 1), step) if len(w[i:i + n]) == n]


def tracked_text(repo: Path) -> str:
    files = subprocess.run(["git", "ls-files", "-z"], cwd=repo, capture_output=True, check=True).stdout.split(b"\0")
    out = []
    for f in files:
        if not f:
            continue
        p = repo / f.decode()
        if p.is_file() and p.stat().st_size < 5_000_000:
            try:
                out.append(norm(p.read_text(errors="ignore")))
            except OSError:
                pass
    return "\n".join(out)


def registered_quotes() -> list[str]:
    """The only licensed text allowed in git: the E1 register's short quotes (at most 25 words each) and their copies in reports."""
    rows = json.loads((ROOT / "compliance" / "controls-register.json").read_text())["rows"]
    qs = [norm(r["quote"]) for r in rows if r["source_kind"] == "primary" and r["standard"] == "PCI DSS"]
    assert qs and all(len(q.split()) <= 25 for q in qs), "register quotes must be at most 25 words"
    return qs


def licensed_windows():
    f = STORE / VERSION / "clauses.jsonl"
    if not f.exists():
        if os.environ.get("E1_ALLOW_MISSING_SOURCES") == "1":
            return None
        raise AssertionError(f"the sealed store is missing: {f}")
    ws = []
    for c in map(json.loads, f.read_text().splitlines()):
        if c["tier"] == "LICENSED":
            ws += windows(c["text"])
    return ws


class NoLicensedTextInGit(unittest.TestCase):
    def test_no_licensed_window_appears_in_any_tracked_file(self):
        ws = licensed_windows()
        if ws is None:
            self.skipTest("the sealed store is not on this machine")
        self.assertGreater(len(ws), 300, "windows were taken from every licensed clause")
        blob = tracked_text(ROOT)
        for q in registered_quotes():
            blob = blob.replace(q, " ")                      # the permitted short quotes may appear; nothing else of the licensed text may
        hits = [w for w in ws if w in blob]
        self.assertEqual(hits[:3], [], f"{len(hits)} licensed windows appear in tracked files")

    def test_the_detector_bites_a_planted_copy_is_found(self):
        ws = licensed_windows()
        if ws is None:
            self.skipTest("the sealed store is not on this machine")
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
            run = lambda *a: subprocess.run(["git", *a], cwd=repo, env=env, check=True, capture_output=True)
            run("init", "-q")
            (repo / "notes.md").write_text("harmless text\n" + ws[len(ws) // 2] + "\nmore text\n")
            run("add", "-A")
            run("commit", "-q", "-m", "x")
            blob = tracked_text(repo)
            self.assertIn(ws[len(ws) // 2], blob)
            self.assertTrue([w for w in ws if w in blob], "a planted licensed window must be detected")


if __name__ == "__main__":
    unittest.main()
