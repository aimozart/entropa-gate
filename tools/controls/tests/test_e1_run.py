"""E1 task 2 glue: collect, write the CBOM, emit the receipt, write the evidence index. Fakes only (no network); the receipt step needs the binary."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from tools.controls import crypto_inventory as ci, e1_run

ROOT = Path(__file__).resolve().parents[3]
FIX = Path(__file__).parent / "fixtures"
PLATINUM = Path(os.environ.get("E1_PLATINUM_BIN") or ROOT / "target" / "release" / "entropa-platinum")


def fake_runner(host, port):
    if host == "localhost":
        return "", "Connect failed: Connection refused", 1
    return (FIX / "s_client_tls13_hybrid.txt").read_text(), "", 0


class RunTests(unittest.TestCase):
    def targets(self):
        return [ci.Target("entropa.space", "entropa.space", 443, "site"), ci.Target("docs.entropa.space", "docs.entropa.space", 443, "site"),
                ci.Target("localhost", "localhost", 443, "local")]

    def test_it_writes_the_cbom_and_the_index_without_a_node(self):
        with tempfile.TemporaryDirectory() as d:
            r = e1_run.run_crypto_inventory(self.targets(), Path(d), node=None, runner=fake_runner, x509=lambda pem: ["entropa.space", "docs.entropa.space"],
                                            now="2026-11-13T21:00:00Z", serial="urn:uuid:11111111-2222-3333-4444-555555555555")
            cb = Path(d) / "cbom-2026-11-13.cdx.json"
            self.assertTrue(cb.exists())
            self.assertEqual(r["cbom_sha256"], __import__("hashlib").sha256(cb.read_bytes()).hexdigest())
            self.assertEqual((r["hosts_in_scope"], r["hosts_answered"]), (3, 2))
            self.assertIsNone(r["receipt"])
            idx = json.loads((Path(d) / "crypto-inventory-2026-11-13.json").read_text())
            self.assertEqual(idx["evidence_kind"], "crypto_inventory")
            self.assertEqual(idx["not_answered"], [{"host": "localhost", "error": "connection_refused"}])
            self.assertEqual([h["host"] for h in idx["hosts"]], ["entropa.space", "docs.entropa.space"])
            self.assertTrue(all(h["tls_version"] == "TLSv1.3" and h["hybrid_pq_kex"] for h in idx["hosts"]))

    def test_a_second_run_on_the_same_day_keeps_the_first_as_the_dated_record(self):
        with tempfile.TemporaryDirectory() as d:
            kw = dict(runner=fake_runner, x509=lambda pem: [], now="2026-11-13T21:00:00Z", serial="urn:uuid:11111111-2222-3333-4444-555555555555")
            a = e1_run.run_crypto_inventory(self.targets(), Path(d), node=None, **kw)
            first = (Path(d) / "cbom-2026-11-13.cdx.json").read_bytes()
            b = e1_run.run_crypto_inventory(self.targets(), Path(d), node=None, **dict(kw, now="2026-11-13T22:00:00Z"))
            self.assertEqual((Path(d) / "cbom-2026-11-13.cdx.json").read_bytes(), first)                    # untouched
            self.assertEqual(a["files"], ["cbom-2026-11-13.cdx.json", "crypto-inventory-2026-11-13.json"])
            self.assertEqual(b["files"], ["cbom-2026-11-13-r2.cdx.json", "crypto-inventory-2026-11-13-r2.json"])
            self.assertEqual(json.loads((Path(d) / "crypto-inventory-2026-11-13-r2.json").read_text())["run_id"], "e1-crypto-inventory-2026-11-13-r2")
            c = e1_run.run_crypto_inventory(self.targets(), Path(d), node=None, **dict(kw, now="2026-11-13T23:00:00Z"))
            self.assertEqual(c["files"][0], "cbom-2026-11-13-r3.cdx.json")

    def test_the_index_states_the_shared_certificate_as_a_fact_and_the_platform_and_classical_findings_plainly(self):
        with tempfile.TemporaryDirectory() as d:
            e1_run.run_crypto_inventory(self.targets(), Path(d), node=None, runner=fake_runner, x509=lambda pem: [], now="2026-11-13T21:00:00Z",
                                        serial="urn:uuid:11111111-2222-3333-4444-555555555555")
            idx = json.loads((Path(d) / "crypto-inventory-2026-11-13.json").read_text())
            shared = idx["facts"]["shared_leaf_certificates"]
            self.assertEqual(len(shared), 1)                                                                   # both fake hosts present the same certificate
            self.assertEqual(shared[0]["hosts"], ["entropa.space", "docs.entropa.space"])
            self.assertRegex(shared[0]["leaf_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(idx["facts"]["shared_certificate_reading"], "a fact about how the certificates are issued, not a gap")
            summ = idx["summary"]
            self.assertEqual((summ["hosts_answered"], summ["hosts_tls13"], summ["hosts_hybrid_kex"], summ["hosts_pq_certificate_signature"]), (2, 2, 2, 0))
            text = " ".join(idx["findings"])
            self.assertIn("hosting platforms", text)
            self.assertIn("not implemented by Entropa", text)
            self.assertIn("OpenSSL 3.5", text)
            self.assertIn("classical", text)
            self.assertIn("no post-quantum signature", text)
            self.assertNotIn("quantum-safe", text.lower())

    def test_the_index_holds_no_private_material_and_no_pem(self):
        with tempfile.TemporaryDirectory() as d:
            e1_run.run_crypto_inventory(self.targets(), Path(d), node=None, runner=fake_runner, x509=lambda pem: [], now="2026-11-13T21:00:00Z",
                                        serial="urn:uuid:11111111-2222-3333-4444-555555555555")
            for f in Path(d).iterdir():
                self.assertNotIn("BEGIN CERTIFICATE", f.read_text())
                self.assertNotIn("PRIVATE KEY", f.read_text())

    @unittest.skipUnless(PLATINUM.exists(), "no entropa-platinum binary")
    def test_the_receipt_is_emitted_and_recorded_in_the_index(self):
        from tools.controls import receipts
        with tempfile.TemporaryDirectory() as d:
            node = receipts.Node(Path(d) / "node", PLATINUM)
            node.init()
            r = e1_run.run_crypto_inventory(self.targets(), Path(d) / "out", node=node, runner=fake_runner, x509=lambda pem: [],
                                            now="2026-11-13T21:00:00Z", serial="urn:uuid:11111111-2222-3333-4444-555555555555")
            self.assertEqual(r["receipt"]["index"], 0)
            idx = json.loads((Path(d) / "out" / "crypto-inventory-2026-11-13.json").read_text())
            self.assertEqual(idx["receipt"]["run_id"], "e1-crypto-inventory-2026-11-13")
            self.assertEqual(idx["receipt"]["subject_hash"], r["receipt"]["subject_hash"])
            self.assertEqual((idx["receipt"]["label"], idx["receipt"]["control"]), ("crypto_inventory", "pci_dss_12_3_3"))
            self.assertEqual(node.verify(), "OK records=1 checkpoints=1")


@unittest.skipUnless(PLATINUM.exists(), "no entropa-platinum binary")
class LogIntegrityRunTests(unittest.TestCase):
    def test_the_run_writes_the_evidence_file_with_both_receipts_and_keeps_the_demo_outside_the_output(self):
        from tools.controls import receipts
        with tempfile.TemporaryDirectory() as d:
            node = receipts.Node(Path(d) / "node", PLATINUM)
            node.init()
            r = e1_run.run_log_integrity(Path(d) / "out", Path(d) / "demo", node, PLATINUM, now="2026-11-13T21:00:00Z", records=3)
            self.assertEqual(r["file"], "log-integrity-2026-11-13.json")
            doc = json.loads((Path(d) / "out" / r["file"]).read_text())
            self.assertEqual([x["what"] for x in doc["receipts"]], ["original_verified", "tampered_copy_failed"])
            self.assertEqual([x["index"] for x in doc["receipts"]], [0, 1])
            self.assertEqual(node.verify(), "OK records=2 checkpoints=2")
            self.assertEqual([p.name for p in (Path(d) / "out").iterdir()], ["log-integrity-2026-11-13.json"])   # no ledger copies in the evidence directory
            self.assertNotIn(str(d), json.dumps(doc))                                                              # no absolute paths


if __name__ == "__main__":
    unittest.main()
