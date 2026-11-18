"""E1 task 1: the control register and the machine check of every quote against its local source text.
Standard library only (pytest is not installed). Run: python3 -m unittest discover -s tools/controls/tests -t ."""
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.controls import quotes, register

ROOT = Path(__file__).resolve().parents[3]
REG = ROOT / "compliance" / "controls-register.json"
RUBRIC = ROOT / "compliance" / "controls-rubric.json"
KEYS = {"id", "standard", "version", "clause", "quote", "anchor", "source_file", "source_sha256", "source_kind", "evidence_type"}


class NormaliseTests(unittest.TestCase):
    def test_whitespace_line_break_hyphenation_quotes_and_dashes_do_not_matter(self):
        a = quotes.compact("High-risk AI systems shall\n technically allow “events” – logs")
        b = quotes.compact("Highrisk AI  systems shall technically allow \"events\" - logs")
        self.assertEqual(a, b)
        self.assertEqual(quotes.compact("high-\nrisk"), quotes.compact("high-risk"))

    def test_a_changed_word_does_matter(self):
        self.assertNotEqual(quotes.compact("shall keep the logs"), quotes.compact("shall keep the log"))
        self.assertNotEqual(quotes.compact("at least six months"), quotes.compact("at least twelve months"))

    def test_case_matters(self):
        self.assertNotEqual(quotes.compact("Audit logs"), quotes.compact("audit logs"))


def entry(**over):
    d = dict(id="X-1", standard="Test", version="1", clause="1", quote="logs shall be protected", anchor="Article 1 Logging",
             source_file="s.txt", source_sha256="", source_kind="primary", evidence_type="log_integrity")
    d.update(over)
    return d


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def src(self, text, name="s.txt"):
        p = self.dir / name
        p.write_text(text)
        return hashlib.sha256(p.read_bytes()).hexdigest()

    def check(self, e, **kw):
        return quotes.verify_entry(e, [self.dir], **kw)

    def test_found_under_its_anchor(self):
        h = self.src("Article 1 Logging 1. The logs shall be protected against change. Article 2 Other")
        r = self.check(entry(source_sha256=h))
        self.assertTrue(r.ok, r.why)

    def test_found_but_under_the_wrong_clause_fails(self):
        h = self.src("Article 1 Logging 1. Nothing relevant here. " + "x " * 4000 + "Article 2 Other 2. The logs shall be protected against change.")
        r = self.check(entry(source_sha256=h), window=1500)
        self.assertFalse(r.ok)
        self.assertIn("anchor", r.why)

    def test_a_wider_window_allows_a_clause_far_below_its_heading(self):
        h = self.src("Article 1 Logging " + "x " * 2000 + "6. The logs shall be protected against change.")
        self.assertFalse(self.check(entry(source_sha256=h), window=1500).ok)
        self.assertTrue(self.check(entry(source_sha256=h), window=9000).ok)

    def test_quote_not_in_source_fails(self):
        h = self.src("Article 1 Logging 1. Something else entirely.")
        r = self.check(entry(source_sha256=h))
        self.assertFalse(r.ok)
        self.assertIn("not found", r.why)

    def test_one_changed_word_fails(self):
        h = self.src("Article 1 Logging 1. The logs shall be protected against change.")
        self.assertFalse(self.check(entry(source_sha256=h, quote="logs shall be protected against changes")).ok)

    def test_wrong_hash_fails_even_when_the_quote_is_there(self):
        self.src("Article 1 Logging 1. The logs shall be protected against change.")
        r = self.check(entry(source_sha256="0" * 64))
        self.assertFalse(r.ok)
        self.assertIn("sha256", r.why)

    def test_missing_source_file_fails_and_says_so(self):
        r = self.check(entry(source_file="nope.txt", source_sha256="0" * 64))
        self.assertFalse(r.ok)
        self.assertIn("missing", r.why)

    def test_hyphenation_and_quote_style_in_the_source_still_match(self):
        h = self.src("Article 1 Logging 1. The “logs” shall be pro-\ntected against change.")
        self.assertTrue(self.check(entry(source_sha256=h, quote='logs" shall be protected against change')).ok)

    def test_html_source_is_read_as_text(self):
        h = self.src("<html><body><p>Article 1 Logging</p><p>The logs &amp; trails shall be protected.</p></body></html>", "s.html")
        r = self.check(entry(source_file="s.html", source_sha256=h, quote="The logs & trails shall be protected"))
        self.assertTrue(r.ok, r.why)

    def test_oscal_source_is_read_per_control_and_the_anchor_is_the_control_id(self):
        cat = {"catalog": {"groups": [{"controls": [
            {"id": "au-9", "parts": [{"name": "statement", "prose": "Protect audit information.", "parts": [{"prose": "and tools"}]}],
             "controls": [{"id": "au-9.3", "parts": [{"name": "statement", "prose": "Implement cryptographic mechanisms."}]}]},
            {"id": "au-10", "parts": [{"name": "statement", "prose": "Provide irrefutable evidence."}]}]}]}}
        h = self.src(json.dumps(cat), "c.json")
        e = entry(source_file="c.json", source_sha256=h, source_kind="primary", anchor="oscal:au-9.3", quote="Implement cryptographic mechanisms")
        self.assertTrue(self.check(e).ok)
        self.assertFalse(self.check(dict(e, anchor="oscal:au-10")).ok)               # the quote is in a different control
        self.assertFalse(self.check(dict(e, anchor="oscal:au-99")).ok)

    def test_pdf_source_goes_through_pdftotext(self):
        text = "Article 1 Logging 1. The logs shall be protected against change."
        ps = f"%!PS\n/Helvetica findfont 12 scalefont setfont\n72 700 moveto ({text}) show\nshowpage\n"
        pdf = self.dir / "s.pdf"
        try:
            subprocess.run(["ps2pdf", "-", str(pdf)], input=ps.encode(), check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("ps2pdf is not available to build a test PDF")
        h = hashlib.sha256(pdf.read_bytes()).hexdigest()
        r = self.check(entry(source_file="s.pdf", source_sha256=h))
        self.assertTrue(r.ok, r.why)


class RegisterShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = register.load_register(REG)
        cls.rubric = json.loads(RUBRIC.read_text())

    def test_every_row_has_exactly_the_agreed_keys_and_types(self):
        for r in self.rows:
            self.assertEqual(set(r), KEYS, r.get("id"))
            for k in KEYS:
                self.assertIsInstance(r[k], str, f"{r['id']}.{k}")
                self.assertTrue(r[k].strip(), f"{r['id']}.{k}")

    def test_quotes_are_at_most_25_words(self):
        for r in self.rows:
            self.assertLessEqual(len(r["quote"].split()), 25, r["id"])

    def test_ids_are_unique_and_match_the_rubric_exactly(self):
        ids = [r["id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), set(self.rubric["controls"]))
        self.assertEqual(len(ids), 17)

    def test_source_kinds_are_primary_or_secondary_and_pinned_by_standard(self):
        kinds = {r["standard"]: r["source_kind"] for r in self.rows}
        self.assertEqual(kinds, {"DORA RTS 2024/1774": "primary", "PCI DSS": "primary", "NIST SP 800-53": "primary",
                                 "EU AI Act": "primary", "HIPAA Security Rule": "secondary"})

    def test_sha256_fields_are_hex_digests(self):
        for r in self.rows:
            self.assertRegex(r["source_sha256"], r"^[0-9a-f]{64}$", r["id"])

    def test_evidence_types_are_rubric_evidence_kinds(self):
        for r in self.rows:
            for t in r["evidence_type"].split(","):
                self.assertIn(t, self.rubric["evidence_kinds"], r["id"])

    def test_no_licensed_pdf_is_in_the_repository(self):
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertEqual([f for f in tracked if f.lower().endswith(".pdf") and "standards" in f.lower()], [])
        self.assertLess(REG.stat().st_size, 40_000)                               # a register of short quotes, not copied text

    def test_loader_rejects_a_row_with_a_long_quote_or_unknown_key(self):
        good = dict(self.rows[0])
        for bad in (dict(good, quote=" ".join(["word"] * 26)), dict(good, extra="x"), {k: v for k, v in good.items() if k != "anchor"}):
            with self.assertRaises(register.RegisterError):
                register.check_rows([bad])


class LiveQuoteTests(unittest.TestCase):
    """Every quote must be found, verbatim (modulo whitespace, hyphenation and typographic quotes), in its local source file."""

    def test_every_quote_is_machine_verified_against_its_source(self):
        rows = register.load_register(REG)
        dirs = register.source_dirs()
        missing_ok = os.environ.get("E1_ALLOW_MISSING_SOURCES") == "1"
        failures = []
        for r in rows:
            res = quotes.verify_entry(r, dirs, window=register.window_for(r))
            if not res.ok and not (missing_ok and res.missing):
                failures.append((r["id"], res.why))
        self.assertEqual(failures, [])

    def test_a_one_word_change_to_a_real_quote_is_caught(self):
        rows = register.load_register(REG)
        dirs = register.source_dirs()
        r = next(x for x in rows if x["id"] == "PCI-10-3-4")
        self.assertTrue(quotes.verify_entry(r, dirs, window=register.window_for(r)).ok)
        bad = dict(r, quote=r["quote"].replace("without generating alerts", "without generating reports"))
        self.assertFalse(quotes.verify_entry(bad, dirs, window=register.window_for(bad)).ok)

    def test_the_rows_cover_all_five_standards(self):
        self.assertEqual({r["standard"] for r in register.load_register(REG)},
                         {"DORA RTS 2024/1774", "PCI DSS", "NIST SP 800-53", "EU AI Act", "HIPAA Security Rule"})


if __name__ == "__main__":
    unittest.main()
