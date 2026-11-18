"""E1 review fix: the evidence the report binds its receipts to must be IN GIT. A clean checkout has to reproduce the committed report, so every
CBOM named by an inventory index must be in the committed tree with the sha256 the index (and the receipt) record. The .gitignore exception for
them must stay narrow: other *.cdx.json files remain ignored."""
import hashlib
import io
import json
import subprocess
import tarfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVID = "docs/evidence/e1"


def git(*args, **kw):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, **kw)


class TrackedEvidenceTests(unittest.TestCase):
    def test_every_cbom_named_by_an_index_is_tracked_by_git(self):
        indexes = sorted((ROOT / EVID).glob("crypto-inventory-*.json"))
        self.assertGreaterEqual(len(indexes), 2)
        for ix in indexes:
            cb = json.loads(ix.read_text())["cbom_file"]
            r = git("ls-files", "--error-unmatch", f"{EVID}/{cb}")
            self.assertEqual(r.returncode, 0, f"{cb} is named by {ix.name} but is not tracked by git: {r.stderr.decode()[:200]}")

    def test_the_committed_tree_alone_holds_each_cbom_with_the_recorded_hash(self):
        """git archive HEAD is what a clean checkout gets: the files must be there and match their index."""
        tar = tarfile.open(fileobj=io.BytesIO(git("archive", "HEAD", EVID).stdout))
        names = set(tar.getnames())
        for ix in sorted((ROOT / EVID).glob("crypto-inventory-*.json")):
            d = json.loads(ix.read_text())
            path = f"{EVID}/{d['cbom_file']}"
            self.assertIn(path, names, f"{path} is not in the committed tree")
            self.assertEqual(hashlib.sha256(tar.extractfile(path).read()).hexdigest(), d["cbom_sha256"], path)

    def test_the_outcome_receipt_is_bound_to_a_tracked_file_whose_hash_matches(self):
        """outcome-E1 was emitted against the report as it was then; that exact version is kept as a dated record so the binding can be checked."""
        d = json.loads((ROOT / EVID / "outcome-E1.json").read_text())
        path = f"{EVID}/{d['report_file']}"
        self.assertEqual(git("ls-files", "--error-unmatch", path).returncode, 0, f"{path} is not tracked")
        self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), d["report_sha256"])
        self.assertIn("at-outcome", d["report_file"])

    def test_the_exception_is_narrow_only_the_e1_evidence_cboms_are_unignored(self):
        self.assertEqual(git("check-ignore", "-q", f"{EVID}/cbom-2099-01-01.cdx.json").returncode, 1)       # 1 = not ignored
        for other in ("docs/evidence/other/x.cdx.json", "target/x.cdx.json", "x.cdx.json", "docs/evidence/e1/sub/x.cdx.json"):
            self.assertEqual(git("check-ignore", "-q", other).returncode, 0, f"{other} must stay ignored")
        self.assertIn("*.cdx.json", (ROOT / ".gitignore").read_text().splitlines())                           # the blanket rule is kept


if __name__ == "__main__":
    unittest.main()
