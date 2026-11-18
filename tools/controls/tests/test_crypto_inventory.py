"""E1 task 2: the crypto-inventory collector (read-only, OUR OWN assets only), its CycloneDX 1.6 CBOM and the receipt of the CBOM's hash.
Fake endpoints first: canned s_client text, an injected runner, and a real local `openssl s_server` with a throwaway self-signed certificate.
Standard library only. Run: python3 -m unittest discover -s tools/controls/tests -t ."""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from tools.controls import cbom, crypto_inventory as ci

ROOT = Path(__file__).resolve().parents[3]
FIX = Path(__file__).parent / "fixtures"
TARGETS = ROOT / "compliance" / "crypto-targets.json"
PLATINUM = Path(os.environ.get("E1_PLATINUM_BIN") or ROOT / "target" / "release" / "entropa-platinum")


class ParserTests(unittest.TestCase):
    def test_tls13_with_a_hybrid_post_quantum_group(self):
        r = ci.parse_s_client((FIX / "s_client_tls13_hybrid.txt").read_text())
        self.assertTrue(r["answered"])
        self.assertEqual((r["tls_version"], r["cipher_suite"]), ("TLSv1.3", "TLS_AES_128_GCM_SHA256"))
        self.assertEqual((r["group"], r["group_source"], r["hybrid_pq_kex"]), ("X25519MLKEM768", "negotiated_tls13_group", True))
        self.assertEqual((r["peer_signature_type"], r["peer_signing_digest"]), ("rsa_pss_rsae_sha256", "SHA256"))
        self.assertEqual((r["verification"], r["verify_return_code"]), ("OK", 0))
        leaf = r["chain"][0]
        self.assertEqual((leaf["subject"], leaf["public_key"], leaf["sigalg"]), ("CN=bigironbank.online", "RSA, 2048 (bit)", "sha256WithRSAEncryption"))
        self.assertEqual((leaf["not_before"], leaf["not_after"]), ("2026-10-21T22:30:07Z", "2027-01-19T23:29:28Z"))
        self.assertEqual(len(r["chain"]), 2)
        self.assertEqual(r["leaf_pem"], "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")

    def test_tls12_classic_group_comes_from_the_server_temp_key_and_is_not_post_quantum(self):
        r = ci.parse_s_client((FIX / "s_client_tls12_classic.txt").read_text())
        self.assertEqual((r["tls_version"], r["cipher_suite"]), ("TLSv1.2", "ECDHE-ECDSA-AES128-GCM-SHA256"))
        self.assertEqual((r["group"], r["group_source"], r["hybrid_pq_kex"]), ("X25519", "server_temp_key", False))
        self.assertEqual(r["verify_return_code"], 62)
        self.assertIn("ostname", r["verification"])
        self.assertEqual(r["chain"][0]["public_key"], "EC, (prime256v1)")
        self.assertEqual(r["chain"][0]["sigalg"], "ecdsa-with-SHA256")

    def test_refused_timeout_and_no_tls_are_recorded_as_not_answering_with_a_reason(self):
        for out, err, rc, why in [("", "Connect failed: Connection refused", 1, "connection_refused"), ("", "", 124, "timeout"),
                                  ("CONNECTED(00000003)\n", "error:0A000126:SSL routines::unexpected eof", 1, "handshake_failure"),
                                  ("", "getaddrinfo: Name or service not known", 1, "dns_failure"), ("garbage", "", 1, "no_tls_session")]:
            r = ci.parse_s_client(out, err, rc)
            self.assertFalse(r["answered"], why)
            self.assertEqual(r["error"], why)

    def test_a_hybrid_group_is_recognised_by_name_only_for_ml_kem(self):
        for g, hyb in [("X25519MLKEM768", True), ("SecP256r1MLKEM768", True), ("MLKEM1024", True), ("X25519", False), ("secp256r1", False), ("ffdhe2048", False)]:
            self.assertEqual(ci.is_hybrid_pq(g), hyb, g)


class TargetsTests(unittest.TestCase):
    def test_the_targets_file_lists_only_our_own_assets(self):
        t = ci.load_targets(TARGETS)
        names = {x.name for x in t}
        self.assertEqual(len(t), 11)
        self.assertTrue({"entropa.space", "bigironbank.online", "hippagrchealthcare.site", "docs.entropa.space", "scryon.entropa.space",
                         "scryon-health.entropa.space", "scryon-council.entropa.space", "localhost"} <= names)
        self.assertTrue(any(x.host.endswith(".a.run.app") and x.host.startswith("entropa-platinum-") for x in t))
        hosts = {x.host for x in t}
        self.assertIn("entropa-ingest-loqc3sut7a-uc.a.run.app", hosts)
        self.assertIn("entropa-transparency-1032137727494.us-central1.run.app", hosts)
        for x in t:
            self.assertTrue(ci.is_own_asset(x.host), x.host)

    def test_a_third_party_host_is_refused_whatever_the_file_says(self):
        for host in ("example.com", "google.com", "evilentropa.space", "entropa.space.evil.com", "8.8.8.8", "10.0.0.1", "192.168.68.58", "api.openai.com",
                     "foo.a.run.app", "entropa-platinum-x.a.run.app.evil.com", ""):
            self.assertFalse(ci.is_own_asset(host), host)
        for host in ("entropa-ingest-evil.a.run.app", "entropa-transparency-1032137727494.us-central1.run.app.evil.com", "entropa-ingest-loqc3sut7a-uc.a.run.app.evil.com",
                     "entropa-transparency-999.us-central1.run.app"):
            self.assertFalse(ci.is_own_asset(host), host)
        for host in ("entropa.space", "www.entropa.space", "docs.entropa.space", "bigironbank.online", "hippagrchealthcare.site", "localhost", "127.0.0.1",
                     "entropa-ingest-loqc3sut7a-uc.a.run.app", "entropa-transparency-1032137727494.us-central1.run.app"):
            self.assertTrue(ci.is_own_asset(host), host)

    def test_load_targets_refuses_a_file_with_a_foreign_host_a_bad_port_or_extra_keys(self):
        with tempfile.TemporaryDirectory() as d:
            for bad in ([{"name": "x", "host": "example.com", "port": 443, "reason": "r"}],
                        [{"name": "x", "host": "entropa.space", "port": 22, "reason": "r"}],
                        [{"name": "x", "host": "entropa.space", "port": 443, "reason": "r", "extra": 1}],
                        [{"name": "x", "host": "entropa.space", "port": 443}], []):
                p = Path(d) / "t.json"
                p.write_text(json.dumps({"targets": bad}))
                with self.assertRaises(ci.TargetError):
                    ci.load_targets(p)

    def test_collect_refuses_a_target_that_is_not_ours_before_any_connection(self):
        calls = []
        runner = lambda host, port: calls.append(host) or ("", "", 1)
        with self.assertRaises(ci.TargetError):
            ci.collect([ci.Target("evil", "example.com", 443, "x")], runner=runner)
        self.assertEqual(calls, [])


class CertFactsTests(unittest.TestCase):
    def test_leaf_fingerprint_is_the_sha256_of_the_der_bytes(self):
        r = ci.parse_s_client((FIX / "s_client_tls13_hybrid.txt").read_text())
        self.assertEqual(ci.leaf_sha256(r["leaf_pem"]), hashlib.sha256(b"\x00\x00\x00").hexdigest())          # the fixture body is AAAA = three zero bytes
        self.assertIsNone(ci.leaf_sha256(None))
        self.assertIsNone(ci.leaf_sha256("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"))

    def test_post_quantum_signature_names_are_recognised_and_classical_ones_are_not(self):
        for n, pq in [("sha256WithRSAEncryption", False), ("ecdsa-with-SHA256", False), ("ML-DSA-65", True), ("mldsa44", True), ("SLH-DSA-SHA2-128s", True),
                      ("ecdsa-with-SHA384", False)]:
            self.assertEqual(ci.is_pq_signature(n), pq, n)


class CollectTests(unittest.TestCase):
    def fake(self, mapping):
        seen = []

        def runner(host, port):
            seen.append((host, port))
            return mapping.get(host, ("", "Connect failed: Connection refused", 1))
        return runner, seen

    def test_one_result_per_target_in_order_and_failures_do_not_stop_the_run(self):
        good = (FIX / "s_client_tls13_hybrid.txt").read_text()
        runner, seen = self.fake({"entropa.space": (good, "", 0)})
        targets = [ci.Target("entropa.space", "entropa.space", 443, "site"), ci.Target("localhost", "localhost", 443, "local")]
        res = ci.collect(targets, runner=runner, x509=lambda pem: ["bigironbank.online", "entropa.space"])
        self.assertEqual([r["name"] for r in res], ["entropa.space", "localhost"])
        self.assertTrue(res[0]["answered"] and not res[1]["answered"])
        self.assertEqual(res[1]["error"], "connection_refused")
        self.assertEqual(res[0]["san"], ["bigironbank.online", "entropa.space"])
        self.assertEqual(res[0]["leaf_sha256"], hashlib.sha256(b"\x00\x00\x00").hexdigest())
        self.assertIs(res[0]["leaf_pq_signature"], False)
        self.assertTrue(res[0]["hostname_in_san"])
        self.assertEqual(seen, [("entropa.space", 443), ("localhost", 443)])

    def test_a_certificate_that_does_not_name_the_host_is_flagged(self):
        good = (FIX / "s_client_tls13_hybrid.txt").read_text()
        runner, _ = self.fake({"entropa.space": (good, "", 0)})
        res = ci.collect([ci.Target("entropa.space", "entropa.space", 443, "site")], runner=runner, x509=lambda pem: ["bigironbank.online"])
        self.assertFalse(res[0]["hostname_in_san"])

    def test_wildcard_san_matches_one_label_only(self):
        self.assertTrue(ci.san_matches("docs.entropa.space", ["*.entropa.space"]))
        self.assertFalse(ci.san_matches("a.b.entropa.space", ["*.entropa.space"]))
        self.assertFalse(ci.san_matches("entropa.space", ["*.entropa.space"]))
        self.assertTrue(ci.san_matches("ENTROPA.space", ["entropa.space"]))

    def test_expiry_days_are_computed_from_a_given_clock(self):
        good = (FIX / "s_client_tls13_hybrid.txt").read_text()
        runner, _ = self.fake({"entropa.space": (good, "", 0)})
        res = ci.collect([ci.Target("entropa.space", "entropa.space", 443, "site")], runner=runner, x509=lambda p: [], now="2027-01-09T23:29:28Z")
        self.assertEqual(res[0]["leaf_days_to_expiry"], 10)

    def test_the_default_runner_only_does_a_handshake_with_a_timeout(self):
        import inspect
        src = inspect.getsource(ci.openssl_runner)
        self.assertIn("s_client", src)
        self.assertIn("timeout", src)
        for forbidden in ("-starttls", "-cipher", "-reconnect", "nmap", "-tlsextdebug", "-msg"):
            self.assertNotIn(forbidden, src)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed for the local fake endpoint")
class LocalEndpointTests(unittest.TestCase):
    """A real TLS server on 127.0.0.1 with a throwaway self-signed ECDSA certificate (made at run time, never stored)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(d / "k.pem"),
                        "-out", str(d / "c.pem"), "-days", "30", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       check=True, capture_output=True)
        cls.port = free_port()
        cls.srv = subprocess.Popen(["openssl", "s_server", "-accept", str(cls.port), "-cert", str(d / "c.pem"), "-key", str(d / "k.pem"), "-www", "-quiet"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.srv.kill()
        cls.srv.wait(timeout=5)
        cls.tmp.cleanup()

    def test_a_real_handshake_is_parsed_end_to_end(self):
        res = ci.collect([ci.Target("localhost", "localhost", self.port, "fake endpoint")], allow_test_port=True)
        r = res[0]
        self.assertTrue(r["answered"], r)
        self.assertEqual(r["tls_version"], "TLSv1.3")
        self.assertTrue(r["cipher_suite"].startswith("TLS_"))
        self.assertTrue(r["group"])
        self.assertEqual(r["chain"][0]["sigalg"], "ecdsa-with-SHA256")
        self.assertEqual(r["chain"][0]["public_key"][:2], "EC")
        self.assertIn("localhost", r["san"])
        self.assertTrue(r["hostname_in_san"])
        self.assertGreaterEqual(r["leaf_days_to_expiry"], 28)

    def test_a_closed_port_is_recorded_not_raised(self):
        r = ci.collect([ci.Target("localhost", "localhost", free_port(), "closed")], allow_test_port=True)[0]
        self.assertFalse(r["answered"])
        self.assertIn(r["error"], ("connection_refused", "handshake_failure", "timeout"))


def sample_results():
    good = ci.parse_s_client((FIX / "s_client_tls13_hybrid.txt").read_text())
    tls12 = ci.parse_s_client((FIX / "s_client_tls12_classic.txt").read_text())
    base = lambda n, h, r: dict(r, name=n, host=h, port=443, san=[h], hostname_in_san=True, leaf_days_to_expiry=80)
    return [base("entropa.space", "entropa.space", good), base("docs.entropa.space", "docs.entropa.space", tls12),
            dict(name="localhost", host="localhost", port=443, answered=False, error="connection_refused")]


class CbomTests(unittest.TestCase):
    def build(self):
        return cbom.build_cbom(sample_results(), timestamp="2026-11-13T21:00:00Z", serial="urn:uuid:11111111-2222-3333-4444-555555555555")

    def test_it_is_a_cyclonedx_1_6_bom_with_cryptographic_assets_only(self):
        b = self.build()
        self.assertEqual((b["bomFormat"], b["specVersion"], b["version"]), ("CycloneDX", "1.6", 1))
        self.assertRegex(b["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
        self.assertEqual(b["metadata"]["timestamp"], "2026-11-13T21:00:00Z")
        self.assertTrue(b["metadata"]["tools"]["components"])
        self.assertTrue(b["components"])
        for c in b["components"]:
            self.assertEqual(c["type"], "cryptographic-asset")
            self.assertIn(c["cryptoProperties"]["assetType"], ("protocol", "algorithm", "certificate"))
            self.assertTrue(c["bom-ref"] and c["name"])

    def test_bom_refs_are_unique_and_every_dependency_points_at_a_real_component(self):
        b = self.build()
        refs = [c["bom-ref"] for c in b["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        for d in b["dependencies"]:
            self.assertIn(d["ref"], refs)
            for x in d.get("dependsOn", []):
                self.assertIn(x, refs)

    def test_each_answering_host_has_a_tls_protocol_asset_a_certificate_and_its_algorithms(self):
        b = self.build()
        protos = [c for c in b["components"] if c["cryptoProperties"]["assetType"] == "protocol"]
        self.assertEqual([p["name"] for p in protos], ["TLS entropa.space:443", "TLS docs.entropa.space:443"])
        p0 = protos[0]["cryptoProperties"]["protocolProperties"]
        self.assertEqual((p0["type"], p0["version"]), ("tls", "1.3"))
        self.assertEqual(p0["cipherSuites"][0]["name"], "TLS_AES_128_GCM_SHA256")
        certs = [c for c in b["components"] if c["cryptoProperties"]["assetType"] == "certificate"]
        self.assertEqual(len(certs), 2)
        cp = certs[0]["cryptoProperties"]["certificateProperties"]
        self.assertEqual(cp["notValidAfter"], "2027-01-19T23:29:28Z")
        self.assertEqual(cp["certificateFormat"], "X.509")
        names = {c["name"] for c in b["components"] if c["cryptoProperties"]["assetType"] == "algorithm"}
        self.assertTrue({"X25519MLKEM768", "X25519", "AES-128-GCM", "sha256WithRSAEncryption"} <= names, names)

    def test_a_host_that_did_not_answer_is_listed_as_not_covered_and_gets_no_invented_crypto(self):
        b = self.build()
        self.assertNotIn("localhost", json.dumps(b["components"]))
        props = {p["name"]: p["value"] for p in b["metadata"]["properties"]}
        self.assertEqual(props["entropa:hosts_in_scope"], "3")
        self.assertEqual(props["entropa:hosts_answered"], "2")
        self.assertEqual(props["entropa:hosts_not_answered"], "localhost:connection_refused")

    def test_the_certificate_fingerprint_is_carried_as_a_property(self):
        res = sample_results()
        res[0]["leaf_sha256"] = "ab" * 32
        b = cbom.build_cbom(res, timestamp="2026-11-13T21:00:00Z", serial="urn:uuid:11111111-2222-3333-4444-555555555555")
        cert = next(c for c in b["components"] if c["cryptoProperties"]["assetType"] == "certificate")
        self.assertIn(("entropa:leaf_sha256", "ab" * 32), [(p["name"], p["value"]) for p in cert["properties"]])

    def test_post_quantum_facts_are_properties_of_the_data_not_claims(self):
        b = self.build()
        flat = {c["name"]: c for c in b["components"]}
        kex = flat["X25519MLKEM768"]["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(kex["primitive"], "key-agree")
        self.assertIn("ML-KEM", json.dumps(flat["X25519MLKEM768"]))
        self.assertNotIn("quantum-safe", json.dumps(b).lower().replace("nistquantumsecuritylevel", ""))

    def test_the_hash_is_the_sha256_of_the_exact_canonical_bytes_and_is_stable(self):
        a, b2 = self.build(), self.build()
        self.assertEqual(cbom.to_bytes(a), cbom.to_bytes(b2))
        self.assertEqual(cbom.sha256_hex(a), hashlib.sha256(cbom.to_bytes(a)).hexdigest())
        changed = json.loads(cbom.to_bytes(a))
        changed["components"][0]["name"] += "x"
        self.assertNotEqual(cbom.sha256_hex(changed), cbom.sha256_hex(a))

    def test_validation_rejects_a_broken_bom(self):
        b = self.build()
        cbom.validate(b)
        for mutate in (lambda d: d.update(specVersion="1.5"), lambda d: d["components"][0].update(type="library"),
                       lambda d: d["dependencies"].append({"ref": "nope"}), lambda d: d["components"].append(dict(d["components"][0])),
                       lambda d: d.pop("serialNumber")):
            bad = json.loads(cbom.to_bytes(b))
            mutate(bad)
            with self.assertRaises(cbom.CbomError):
                cbom.validate(bad)

    def test_a_run_with_no_answering_host_is_refused_not_written(self):
        with self.assertRaises(cbom.CbomError):
            cbom.build_cbom([dict(name="x", host="x", port=443, answered=False, error="timeout")], timestamp="2026-11-13T21:00:00Z", serial="urn:uuid:11111111-2222-3333-4444-555555555555")


@unittest.skipUnless(PLATINUM.exists(), "no entropa-platinum binary built from this branch (./run-cargo.sh build --release -p entropa-platinum)")
class ReceiptTests(unittest.TestCase):
    def test_the_cbom_hash_gets_a_receipt_that_verifies_offline(self):
        from tools.controls import receipts
        with tempfile.TemporaryDirectory() as d:
            node = receipts.Node(Path(d) / "node", PLATINUM)
            node.init()
            h = cbom.sha256_hex(cbom.build_cbom(sample_results(), timestamp="2026-11-13T21:00:00Z", serial="urn:uuid:11111111-2222-3333-4444-555555555555"))
            r = node.emit_crypto_inventory(cbom_sha256=h, hosts_in_scope=3, hosts_answered=2, run_id="e1-test-crypto-inventory")
            self.assertEqual((r["index"], r["size"]), (0, 1))
            self.assertRegex(r["subject_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(node.verify(), "OK records=1 checkpoints=1")
            rec = node.export()["records"][0]
            self.assertEqual((rec["kind"], rec["label"]), ("evidence.control_check", "crypto_inventory"))
            self.assertIn("Crypto inventory", rec["plain"])
            self.assertIn("3 hosts examined", rec["plain"])
            self.assertIn("PCI DSS 12.3.3", rec["plain"])

    def test_a_run_where_a_host_did_not_answer_is_recorded_as_flagged_not_passed(self):
        from tools.controls import receipts
        with tempfile.TemporaryDirectory() as d:
            node = receipts.Node(Path(d) / "node", PLATINUM)
            node.init()
            node.emit_crypto_inventory(cbom_sha256="a" * 64, hosts_in_scope=9, hosts_answered=8, run_id="e1-test-2")
            rec = node.export()["records"][0]
            self.assertIn("9 hosts examined", rec["plain"])
            self.assertIn("1 did not answer", rec["plain"])


if __name__ == "__main__":
    unittest.main()
