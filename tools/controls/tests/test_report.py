"""E1 task 4: the report generator. Register rows joined to receipts, status by the rubric that was fixed BEFORE any result, known gaps first.
Receipts are CHECKED against the node (label, control, subject hash, and offline verification of the whole ledger), never assumed."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.controls import e1_run, register, report

ROOT = Path(__file__).resolve().parents[3]
RUBRIC = json.loads((ROOT / "compliance" / "controls-rubric.json").read_text())
REG = ROOT / "compliance" / "controls-register.json"
EVID = ROOT / "docs" / "evidence" / "e1"
PLATINUM = Path(os.environ.get("E1_PLATINUM_BIN") or ROOT / "target" / "release" / "entropa-platinum")
SCRATCH = Path(os.environ.get("E1_NODE_DIR") or Path.home() / ".cache" / "build" / "e1-scratch-node")
needs_bin = unittest.skipUnless(PLATINUM.exists(), "no entropa-platinum binary")
FIX = ROOT / "tools" / "controls" / "tests" / "fixtures"


class StatusTests(unittest.TestCase):
    def st(self, cid, present, quote_ok=True, kind="primary"):
        return report.row_status(cid, RUBRIC, set(present), quote_ok, kind)

    def test_met_needs_every_required_kind_no_gap_and_a_verified_primary_quote(self):
        r = self.st("NIST-AU-9-3", {"signed_records", "log_tamper_detection"})
        self.assertEqual(r["status"], "MET BY EVIDENCE")
        self.assertEqual((r["missing"], r["gaps"]), ([], []))

    def test_a_secondary_source_caps_the_row_at_partial_even_with_everything_present(self):
        r = self.st("HIPAA-164-312-c2", {"log_tamper_detection"}, kind="secondary")
        self.assertEqual(r["status"], "PARTIAL")
        self.assertIn("secondary", r["why"])

    def test_an_unverified_quote_caps_the_row_at_partial(self):
        r = self.st("NIST-AU-9-3", {"signed_records", "log_tamper_detection"}, quote_ok=False)
        self.assertEqual(r["status"], "PARTIAL")
        self.assertIn("quote", r["why"])

    def test_an_attached_known_gap_caps_the_row_at_partial(self):
        r = self.st("NIST-AU-9-2", {"separate_storage"})                       # the rubric attaches witness_only_ai_ledger
        self.assertEqual(r["status"], "PARTIAL")
        self.assertEqual(r["gaps"], ["witness_only_ai_ledger"])

    def test_some_required_kinds_present_is_partial_and_lists_what_is_missing(self):
        r = self.st("PCI-10-3-4", {"log_tamper_detection"})
        self.assertEqual(r["status"], "PARTIAL")
        self.assertEqual((r["covered"], r["missing"]), (["log_tamper_detection"], ["alerting_on_change"]))

    def test_no_required_kind_present_is_a_gap(self):
        for cid in ("PCI-10-5-1", "EUAIA-19", "EUAIA-26-6", "DORA-7"):
            self.assertEqual(self.st(cid, {"crypto_inventory", "log_tamper_detection", "signed_records"})["status"], "GAP", cid)

    def test_evidence_that_the_row_does_not_ask_for_does_not_count(self):
        self.assertEqual(self.st("PCI-10-5-1", {"signed_records"})["status"], "GAP")

    def test_every_rubric_row_gets_a_status_for_any_evidence_set(self):
        kinds = list(RUBRIC["evidence_kinds"])
        for cid in RUBRIC["controls"]:
            for present in (set(), set(kinds)):
                self.assertIn(self.st(cid, present)["status"], report.STATUSES)

    def test_an_unknown_control_is_refused(self):
        with self.assertRaises(report.ReportError):
            self.st("NOPE-1", set())


def make_evidence(d: Path):
    """A node plus a crypto inventory run (fake endpoints) and a log-integrity demo, as the real runs do."""
    from tools.controls import crypto_inventory as ci, receipts
    node = receipts.Node(d / "node", PLATINUM)
    node.init()
    runner = lambda host, port: ((FIX / "s_client_tls13_hybrid.txt").read_text(), "", 0)
    ts = [ci.Target("entropa.space", "entropa.space", 443, "site"), ci.Target("docs.entropa.space", "docs.entropa.space", 443, "site")]
    e1_run.run_crypto_inventory(ts, d / "evidence", node, runner=runner, x509=lambda p: ["entropa.space", "docs.entropa.space"], now="2026-11-13T21:00:00Z",
                                serial="urn:uuid:11111111-2222-3333-4444-555555555555")
    e1_run.run_log_integrity(d / "evidence", d / "demo", node, PLATINUM, now="2026-11-13T21:05:00Z", records=3)
    return node, d / "evidence"


@needs_bin
class EvidenceTests(unittest.TestCase):
    def test_receipts_that_verify_make_their_kinds_present_and_the_rest_stay_absent_with_a_reason(self):
        with tempfile.TemporaryDirectory() as d:
            node, ev = make_evidence(Path(d))
            e = report.load_evidence(ev, node)
            for k in ("crypto_inventory", "log_tamper_detection", "signed_records"):
                self.assertTrue(e[k]["present"], (k, e[k]))
                self.assertTrue(e[k]["receipts"])
            self.assertFalse(e["separate_storage"]["present"])
            self.assertIn("documented or stated", e["separate_storage"]["why"])
            for k in ("retention_evidence", "key_lifecycle_evidence", "crypto_policy_document", "alerting_on_change"):
                self.assertFalse(e[k]["present"], k)
                self.assertIn("not produced by E1", e[k]["why"])

    def test_a_changed_cbom_file_makes_the_crypto_inventory_absent(self):
        with tempfile.TemporaryDirectory() as d:
            node, ev = make_evidence(Path(d))
            f = next(ev.glob("cbom-*.cdx.json"))
            f.write_bytes(f.read_bytes().replace(b"CycloneDX", b"CycloneDx", 1))
            e = report.load_evidence(ev, node)
            self.assertFalse(e["crypto_inventory"]["present"])
            self.assertIn("sha256", e["crypto_inventory"]["why"])
            self.assertTrue(e["log_tamper_detection"]["present"])

    def test_an_edited_receipt_in_the_index_makes_the_kind_absent(self):
        with tempfile.TemporaryDirectory() as d:
            node, ev = make_evidence(Path(d))
            f = next(ev.glob("crypto-inventory-*.json"))
            doc = json.loads(f.read_text())
            doc["receipt"]["subject_hash"] = "0" * 64
            f.write_text(json.dumps(doc))
            e = report.load_evidence(ev, node)
            self.assertFalse(e["crypto_inventory"]["present"])
            self.assertIn("subject hash", e["crypto_inventory"]["why"])

    def test_a_ledger_that_does_not_verify_offline_removes_every_receipt_backed_kind(self):
        from tools.controls import receipts
        with tempfile.TemporaryDirectory() as d:
            node, ev = make_evidence(Path(d))
            bad = Path(d) / "badnode"
            shutil.copytree(node.dir, bad)
            f = bad / "evidence-ledger" / "records.log"
            data = bytearray(f.read_bytes())
            data[len(data) // 2] ^= 0x01
            f.write_bytes(bytes(data))
            e = report.load_evidence(ev, receipts.Node(bad, PLATINUM))
            for k in ("crypto_inventory", "log_tamper_detection", "signed_records"):
                self.assertFalse(e[k]["present"], k)
                self.assertIn("did not verify", e[k]["why"])

    def test_with_no_node_nothing_is_present(self):
        with tempfile.TemporaryDirectory() as d:
            _, ev = make_evidence(Path(d))
            e = report.load_evidence(ev, None)
            self.assertFalse(any(v["present"] for v in e.values()))

    def test_the_latest_crypto_inventory_counts_and_the_earlier_one_is_listed_as_a_dated_record(self):
        from tools.controls import crypto_inventory as ci
        with tempfile.TemporaryDirectory() as d:
            node, ev = make_evidence(Path(d))
            runner = lambda host, port: ((FIX / "s_client_tls13_hybrid.txt").read_text(), "", 0)
            e1_run.run_crypto_inventory([ci.Target("entropa.space", "entropa.space", 443, "site")], ev, node, runner=runner, x509=lambda p: [],
                                        now="2026-11-13T22:00:00Z", serial="urn:uuid:11111111-2222-3333-4444-555555555555")
            e = report.load_evidence(ev, node)
            self.assertTrue(e["crypto_inventory"]["present"])
            self.assertEqual(e["crypto_inventory"]["latest"], "crypto-inventory-2026-11-13-r2.json")
            self.assertEqual(e["crypto_inventory"]["dated_records"], ["crypto-inventory-2026-11-13.json"])


def fake_evidence(present=()):
    return {k: dict(present=k in present, why="test", receipts=[], files=[]) for k in RUBRIC["evidence_kinds"]}


def ok_quotes():
    return {r["id"]: dict(ok=True, why="found under its anchor") for r in register.load_register(REG)}


class ReportTests(unittest.TestCase):
    def build(self, present=("crypto_inventory", "log_tamper_detection", "signed_records")):
        return report.build_report(register.load_register(REG), RUBRIC, fake_evidence(present), ok_quotes(), generated="2026-11-13T22:00:00Z",
                                   history=[dict(what="E-LABELS-2 RED", old="23dcdca", new="e54ac07")], findings=["a finding"])

    def test_json_has_known_gaps_first_every_row_and_consistent_counts(self):
        r = self.build()
        self.assertEqual(list(r)[:4], ["report_version", "generated", "wording", "known_gaps"])
        self.assertEqual({g["id"] for g in r["known_gaps"]}, set(RUBRIC["known_gaps"]))
        self.assertEqual(len(r["rows"]), 17)
        counts = {s: sum(x["status"] == s for x in r["rows"]) for s in report.STATUSES}
        self.assertEqual({s: r["summary"][s] for s in report.STATUSES}, counts)
        self.assertEqual(sum(counts.values()), 17)
        self.assertEqual(r["summary"]["quotes_verified"], "17/17")
        self.assertEqual(r["history"][0]["new"], "e54ac07")

    def test_a_row_lists_what_it_covers_what_is_missing_and_the_receipts_behind_it(self):
        ev = fake_evidence({"signed_records", "log_tamper_detection"})
        ev["signed_records"]["receipts"] = [dict(index=2)]
        ev["log_tamper_detection"]["receipts"] = [dict(index=2), dict(index=3)]
        r = report.build_report(register.load_register(REG), RUBRIC, ev, ok_quotes(), generated="2026-11-13T22:00:00Z", history=[], findings=[])
        row = next(x for x in r["rows"] if x["id"] == "NIST-AU-9-3")
        self.assertEqual(row["status"], "MET BY EVIDENCE")
        self.assertEqual(row["receipts"], [2, 3])
        self.assertTrue(row["quote_verified"])
        self.assertIn("demo node", row["caveat"])
        self.assertIn("no production ledger", row["caveat"])
        self.assertNotIn("caveat", next(x for x in r["rows"] if x["id"] == "PCI-10-5-1"))
        md = report.to_markdown(r)
        self.assertIn("NIST-AU-9-3: every required evidence kind", md)
        self.assertIn("Caveat: the mechanism was demonstrated on a demo node", md)
        row = next(x for x in r["rows"] if x["id"] == "PCI-10-5-1")
        self.assertEqual((row["status"], row["receipts"]), ("GAP", []))

    def test_markdown_puts_the_known_gaps_before_the_row_table_and_says_what_it_is_not(self):
        md = report.to_markdown(self.build())
        self.assertLess(md.index("## Known gaps"), md.index("## Control rows"))
        self.assertIn("evidence mapped to the control", md)
        self.assertIn("not an assessment of compliance", md)
        for g in RUBRIC["known_gaps"].values():
            self.assertIn(g["text"], md)
        self.assertIn("23dcdca", md)
        self.assertIn("e54ac07", md)

    def test_markdown_and_json_agree_on_every_status(self):
        r = self.build()
        md = report.to_markdown(r)
        for row in r["rows"]:
            line = next(l for l in md.splitlines() if l.startswith(f"| {row['id']} "))
            self.assertIn(row["status"], line)

    def test_the_report_passes_the_repository_wording_check(self):
        script = ROOT / "scripts" / "governance-checks.sh"
        if not script.exists():
            self.skipTest("no governance-checks.sh")
        with tempfile.TemporaryDirectory() as d:
            md = Path(d) / "r.md"
            md.write_text(report.to_markdown(self.build()))
            p = subprocess.run([str(script), "wording", str(md)], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIsNone(re.search(r"\b(certified|certification)\b", report.to_markdown(self.build()), re.I))

    def test_the_limits_carry_the_dated_retirement_note_in_json_markdown_and_the_committed_report(self):
        r = self.build()
        notes = [x for x in r["limits"] if "hippagrchealthcare.site was retired" in x]
        self.assertEqual(len(notes), 1)
        for needle in ("2026-11-13", "hosting site deleted, DNS kept", "bigironbank.online is being retired", "kept as the dated record"):
            self.assertIn(needle, notes[0])
        self.assertIn(notes[0], report.to_markdown(r))
        committed = json.loads((EVID / "controls-report.json").read_text())
        self.assertIn(notes[0], committed["limits"])
        self.assertIn(notes[0], (EVID / "controls-report.md").read_text())

    def test_an_unverified_quote_is_shown_and_caps_its_row(self):
        q = ok_quotes()
        q["NIST-AU-9-3"] = dict(ok=False, why="quote not found")
        r = report.build_report(register.load_register(REG), RUBRIC, fake_evidence({"signed_records", "log_tamper_detection"}), q, generated="2026-11-13T22:00:00Z",
                                history=[], findings=[])
        row = next(x for x in r["rows"] if x["id"] == "NIST-AU-9-3")
        self.assertEqual((row["status"], row["quote_verified"]), ("PARTIAL", False))
        self.assertEqual(r["summary"]["quotes_verified"], "16/17")

    def test_with_no_evidence_nothing_is_met_and_everything_is_a_gap(self):
        r = self.build(present=())
        self.assertEqual({x["status"] for x in r["rows"]}, {"GAP"})

    def test_write_produces_markdown_and_json_with_the_same_content(self):
        with tempfile.TemporaryDirectory() as d:
            md, js = report.write(self.build(), Path(d))
            self.assertEqual((md.name, js.name), ("controls-report.md", "controls-report.json"))
            self.assertEqual(json.loads(js.read_text())["summary"]["quotes_verified"], "17/17")
            self.assertIn("## Known gaps", md.read_text())


@needs_bin
@unittest.skipUnless((SCRATCH / "platinum.key").exists() and (EVID / "log-integrity-2026-11-13.json").exists(), "the real E1 evidence and scratch node are not here")
class RealEvidenceTests(unittest.TestCase):
    """The measured outcome on the real evidence, pinned so a later change shows up. Plan vs outcome is written up in a stage record (not published)."""

    def test_the_measured_statuses(self):
        from tools.controls import receipts
        node = receipts.Node(SCRATCH, PLATINUM)
        e = report.load_evidence(EVID, node)
        quotes = {r["id"]: dict(ok=True, why="") for r in register.load_register(REG)}
        r = report.build_report(register.load_register(REG), RUBRIC, e, quotes, generated="2026-11-13T23:00:00Z", history=[], findings=[])
        by = {x["id"]: x["status"] for x in r["rows"]}
        self.assertEqual([k for k, v in by.items() if v == "MET BY EVIDENCE"], ["NIST-AU-9-3"])
        self.assertEqual(sorted(k for k, v in by.items() if v == "GAP"), ["DORA-7", "EUAIA-19", "EUAIA-26-6", "NIST-AU-9-2", "PCI-10-5-1"])
        self.assertEqual(sum(v == "PARTIAL" for v in by.values()), 11)
        self.assertNotEqual(by["HIPAA-164-312-c2"], "MET BY EVIDENCE")


if __name__ == "__main__":
    unittest.main()
