"""E1 task 3: the log-integrity demonstration. A dedicated DEMO node (its own throwaway key, never a production ledger) is copied, one byte of the
COPY is changed, and offline verification must fail on the copy and still pass on the original. Needs the entropa-platinum binary built from this
branch; skipped (with the reason) when it is absent. Run: python3 -m unittest discover -s tools/controls/tests -t ."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from tools.controls import log_integrity as li, receipts

ROOT = Path(__file__).resolve().parents[3]
PLATINUM = Path(os.environ.get("E1_PLATINUM_BIN") or ROOT / "target" / "release" / "entropa-platinum")
needs_bin = unittest.skipUnless(PLATINUM.exists(), "no entropa-platinum binary (./run-cargo.sh build --release -p entropa-platinum)")


def tree_hash(d: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(x for x in Path(d).rglob("*") if x.is_file() and x.name != "platinum.key"):
        h.update(str(p.relative_to(d)).encode())
        h.update(p.read_bytes())
    return h.hexdigest()


@needs_bin
class DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.work = Path(cls.tmp.name)
        cls.res = li.run_demo(PLATINUM, cls.work, records=5)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_original_verifies_before_and_after_and_the_tampered_copy_fails(self):
        r = self.res
        self.assertEqual(r["original_verify_before"], "OK records=5 checkpoints=5")
        self.assertEqual(r["original_verify_after"], "OK records=5 checkpoints=5")
        self.assertFalse(r["copy_verify"]["ok"])
        self.assertTrue(r["copy_verify"]["message"])
        self.assertNotIn("OK records", r["copy_verify"]["message"])

    def test_exactly_one_byte_differs_and_the_size_is_unchanged(self):
        t = self.res["tamper"]
        self.assertEqual((t["differing_bytes"], t["size_equal"]), (1, True))
        self.assertNotEqual(t["old_byte"], t["new_byte"])
        a = (self.work / "original" / t["file"]).read_bytes()
        b = (self.work / "copy" / t["file"]).read_bytes()
        self.assertEqual(len(a), len(b))
        self.assertEqual(sum(x != y for x, y in zip(a, b)), 1)
        self.assertEqual(a[t["offset"]], int(t["old_byte"], 16))
        self.assertEqual(b[t["offset"]], int(t["new_byte"], 16))

    def test_the_original_directory_is_byte_for_byte_untouched(self):
        self.assertEqual(self.res["original_tree_sha256_before"], self.res["original_tree_sha256_after"])
        self.assertEqual(tree_hash(self.work / "original"), self.res["original_tree_sha256_after"])

    def test_a_flipped_bit_anywhere_in_the_evidence_ledger_is_detected(self):
        outcomes = self.res["positions"]
        self.assertGreaterEqual(len(outcomes), 3)
        for o in outcomes:
            if o["kind"] == "flip":
                self.assertTrue(o["detected"], o)

    def test_append_and_truncate_are_measured_and_reported_whatever_the_result(self):
        kinds = {o["kind"]: o for o in self.res["positions"]}
        self.assertIn("append_byte", kinds)
        self.assertIn("truncate_last_byte", kinds)
        for k in ("append_byte", "truncate_last_byte"):
            self.assertIsInstance(kinds[k]["detected"], bool)
            self.assertTrue(kinds[k]["verify_message"])

    def test_the_tamper_function_refuses_any_directory_that_is_not_a_demo_copy(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "evidence-ledger").mkdir()
            (Path(d) / "evidence-ledger" / "x").write_bytes(b"0123456789")
            with self.assertRaises(li.NotADemoCopy):
                li.tamper_copy(Path(d))
            self.assertEqual((Path(d) / "evidence-ledger" / "x").read_bytes(), b"0123456789")
        for p in ("~/.local/share/hippagrchealthcare-evidence", "~/.cache/build/e1-scratch-node"):
            with self.assertRaises(li.NotADemoCopy):
                li.tamper_copy(Path(p).expanduser())

    def test_measured_facts_two_ledgers_one_key_no_witness_and_no_separate_storage(self):
        f = self.res["facts"]["measured_on_the_demo_node"]
        self.assertEqual(f["ledger_directories"], ["evidence-ledger", "ledger"])
        self.assertTrue(f["same_key_id_across_both_ledgers"])
        self.assertEqual(f["signing_key_files"], ["platinum.key"])
        self.assertEqual(f["witnesses"], [])
        self.assertEqual(f["signature_algorithm"], "ML-DSA-65")
        self.assertFalse(f["separate_storage_demonstrated"])

    def test_stated_facts_are_labelled_stated_not_measured_with_their_source(self):
        s = self.res["facts"]["stated_not_measured_by_this_demo"]
        text = json.dumps(s)
        self.assertIn("three ledgers share one signing key", text)
        self.assertIn("only the AI ledger is witnessed", text)
        for row in s:
            self.assertIs(row["measured"], False)
            self.assertTrue(row["source"])

    def test_the_result_holds_no_key_material_and_no_ledger_content(self):
        text = json.dumps(self.res)
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn("record_hex", text)
        self.assertNotIn("signature", text.lower().replace("signature_algorithm", ""))
        self.assertNotRegex(text, r"[0-9a-f]{128}")                                  # no long hex blobs (keys, signatures, records)


@needs_bin
class ReceiptTests(unittest.TestCase):
    def test_the_two_receipts_verify_and_read_as_verified_and_failed(self):
        with tempfile.TemporaryDirectory() as d:
            res = li.run_demo(PLATINUM, Path(d) / "work", records=3)
            node = receipts.Node(Path(d) / "node", PLATINUM)
            node.init()
            got = li.emit_receipts(node, res, run_id="e1-test-log-integrity")
            self.assertEqual([g["index"] for g in got], [0, 1])
            self.assertEqual(node.verify(), "OK records=2 checkpoints=2")
            recs = node.export()["records"]
            self.assertTrue(all(r["label"] == "log_integrity_check" and r["kind"] == "evidence.control_check" for r in recs))
            self.assertIn("verified from start to end", recs[0]["plain"])
            self.assertIn("verification failed", recs[1]["plain"])
            self.assertIn("NIST SP 800-53 AU-9", recs[0]["plain"] + recs[1]["plain"])

    def test_receipts_are_refused_when_the_demo_did_not_behave_as_expected(self):
        with tempfile.TemporaryDirectory() as d:
            node = receipts.Node(Path(d) / "node", PLATINUM)
            node.init()
            bad = dict(original_verify_before="OK records=3 checkpoints=3", original_verify_after="OK records=3 checkpoints=3",
                       copy_verify=dict(ok=True, message="OK records=3 checkpoints=3"), tamper=dict(differing_bytes=1))
            with self.assertRaises(li.DemoFailed):
                li.emit_receipts(node, bad, run_id="e1-test-bad")
            self.assertEqual(node.verify(), "OK records=0 checkpoints=0")


class WriteTests(unittest.TestCase):
    @unittest.skipUnless(PLATINUM.exists(), "no binary")
    def test_the_evidence_file_is_written_once_per_run_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out"
            res = li.run_demo(PLATINUM, Path(d) / "w1", records=3)
            a = li.write_evidence(res, out, "2026-11-13T21:00:00Z", receipts_list=[])
            b = li.write_evidence(res, out, "2026-11-13T22:00:00Z", receipts_list=[])
            self.assertEqual((a.name, b.name), ("log-integrity-2026-11-13.json", "log-integrity-2026-11-13-r2.json"))
            self.assertEqual(json.loads(a.read_text())["evidence_kind"], "log_tamper_detection")


if __name__ == "__main__":
    unittest.main()
