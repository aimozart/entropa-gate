"""R1: the question sets were frozen BEFORE any retrieval code existed, and the plan records the freeze commit. Needs git history (host side:
git is not usable inside the build container because the repository is a worktree). These tests FAIL, not skip, when the history is missing."""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FROZEN = "crates/standards/eval/FROZEN.json"
RETRIEVAL_FILES = ["src/retrieve.rs", "src/bm25.rs", "src/mcp.rs", "src/cite.rs", "src/bin/entropa-standards-mcp.rs"]


def git(*args):
    p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout.strip()


def freeze_commit():
    rc, out = git("log", "--diff-filter=A", "--format=%H", "--", FROZEN)
    commits = [c for c in out.splitlines() if c]
    return commits[-1] if rc == 0 and commits else None


class FreezeTests(unittest.TestCase):
    def test_the_freeze_commit_exists(self):
        self.assertIsNotNone(freeze_commit(), f"{FROZEN} has not been committed: the sets are not frozen yet")

    def test_no_retrieval_code_existed_at_the_freeze_commit(self):
        c = freeze_commit()
        self.assertIsNotNone(c)
        for f in RETRIEVAL_FILES:
            rc, _ = git("cat-file", "-e", f"{c}:crates/standards/{f}")
            self.assertNotEqual(rc, 0, f"{f} already existed at the freeze commit {c[:12]}")

    def test_the_frozen_files_are_unchanged_since_the_freeze_commit(self):
        c = freeze_commit()
        self.assertIsNotNone(c)
        rc, out = git("diff", "--name-only", c, "HEAD", "--", "crates/standards/eval")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "", f"files under crates/standards/eval changed after the freeze: {out}")

    def test_the_plan_records_the_freeze_commit(self):
        c = freeze_commit()
        self.assertIsNotNone(c)
        plan = (ROOT / "docs" / "plans" / "R1.md").read_text()
        self.assertIn(f"Freeze commit: {c[:12]}", plan)


if __name__ == "__main__":
    unittest.main()
