"""Red tests for tools/results/make_public_md.py: docs/public/RESULTS.md is generated from results.json, so its numbers cannot drift."""
import json, os, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
TOOL = os.path.join(HERE, "make_public_md.py")
RESULTS = os.path.join(ROOT, "docs", "results", "results.json")
COMMITTED = os.path.join(ROOT, "docs", "public", "RESULTS.md")
TMP = os.environ.get("TMPDIR", "/tmp")


def gen(results=RESULTS):
    out = os.path.join(tempfile.mkdtemp(prefix="pubmd-", dir=TMP), "RESULTS.md")
    p = subprocess.run([sys.executable, TOOL, "--results", results, "--out", out], capture_output=True, text=True)
    return p.returncode, p.stderr, out


class T(unittest.TestCase):
    def test_m1_the_committed_page_equals_a_fresh_generation(self):
        rc, err, out = gen()
        self.assertEqual(rc, 0, err)
        self.assertEqual(open(out).read(), open(COMMITTED).read())

    def test_m2_failures_come_first_all_17_and_every_bullet_has_an_evidence_pointer(self):
        rc, err, out = gen()
        self.assertEqual(rc, 0, err)
        text = open(out).read()
        self.assertIn("tested against", text.lower())
        self.assertLess(text.index("## Failed bars"), text.index("## All runs"))
        failed_part = text.split("## All runs")[0]
        self.assertEqual(sum(1 for l in failed_part.splitlines() if l.startswith("- ")), 25)  # Test change (RESULTS-V3): 21 + 4 failed bars
        for l in text.splitlines():
            if l.startswith("- "):
                self.assertIn("[evidence: docs/results/results.json]", l)

    def test_m3_every_failed_bar_of_the_data_appears_with_its_counts(self):
        data = json.load(open(RESULTS))
        text = open(gen()[2]).read()
        for r in data["rows"]:
            for b in r["bars"]:
                if b["result"] == "fail":
                    want = (f"{b['numerator']}/{b['denominator']}" if b["numerator"] is not None else b["value"])
                    line = next((l for l in text.splitlines() if l.startswith("- ") and r["id"] in l and b["name"] in l), None)
                    self.assertIsNotNone(line, f"{r['id']} {b['name']}")
                    self.assertIn(want, line)

    def test_m4_no_banned_words_no_emails_no_paths_and_a_bad_input_writes_nothing(self):
        text = open(gen()[2]).read().lower()
        for w in ("secure", "compliant", "certified"):
            self.assertNotRegex(text, r"\b" + w + r"\b")
        self.assertNotIn("@", text)
        self.assertNotIn("/home/", text)
        d = json.load(open(RESULTS))
        d["schema"] = "results-0"
        f = tempfile.NamedTemporaryFile("w", suffix=".json", dir=TMP, delete=False)
        json.dump(d, f)
        f.close()
        rc, err, out = gen(f.name)
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
