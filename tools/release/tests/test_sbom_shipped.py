"""S2 finish: the SBOM of the shipped closure (not the whole lock): a stage record (not published). Synthetic metadata and lock text; one real-workspace test."""
import json
import subprocess
import unittest
from pathlib import Path

from tools.release import licences as L
from tools.release import sbom_shipped as S

ROOT = Path(__file__).resolve().parents[3]
CRATES = "registry+https://github.com/rust-lang/crates.io-index"


def pkg(name, lic, version="1.0.0", source=CRATES):
    return {"id": f"{name} {version}", "name": name, "version": version, "license": lic, "source": source}


def meta(packages, edges, roots):
    ids = {p["name"]: p["id"] for p in packages}
    nodes = [{"id": p["id"], "deps": [{"pkg": ids[d], "dep_kinds": [{"kind": k, "target": None}]} for d, k in edges.get(p["name"], [])]} for p in packages]
    return {"packages": packages, "resolve": {"nodes": nodes}, "workspace_members": [ids[r] for r in roots]}


LOCK = '''version = 4

[[package]]
name = "a"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%s"

[[package]]
name = "b"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%s"

[[package]]
name = "app"
version = "0.2.0"
''' % ("ab" * 32, "cd" * 32)


def sample():
    ps = [pkg("app", "MIT", "0.2.0", None), pkg("a", "Apache-2.0 OR MIT"), pkg("b", "ISC", "2.0.0"), pkg("devonly", "GPL-3.0")]
    return meta(ps, {"app": [("a", None), ("b", "build"), ("devonly", "dev")]}, ["app"])


class Bom(unittest.TestCase):
    def test_shape_and_components(self):
        b = S.build(L.inventory(sample(), ["app"]), LOCK, "entropa-gate", "0.2.0")
        self.assertEqual((b["bomFormat"], b["specVersion"], b["version"]), ("CycloneDX", "1.5", 1))
        self.assertNotIn("serialNumber", b, "no random serial")
        self.assertNotIn("timestamp", json.dumps(b), "no timestamp")
        names = [c["name"] for c in b["components"]]
        self.assertEqual(names, ["a", "app", "b"], "sorted; dev-only excluded")
        a = next(c for c in b["components"] if c["name"] == "a")
        self.assertEqual(a["purl"], "pkg:cargo/a@1.0.0")
        self.assertEqual(a["hashes"], [{"alg": "SHA-256", "content": "ab" * 32}])
        self.assertEqual(a["licenses"], [{"expression": "Apache-2.0 OR MIT"}])
        app = next(c for c in b["components"] if c["name"] == "app")
        self.assertNotIn("hashes", app, "our own crate has no registry checksum")
        self.assertIn({"name": "entropa:workspace", "value": "true"}, app["properties"])

    def test_deterministic(self):
        inv = L.inventory(sample(), ["app"])
        self.assertEqual(S.render(S.build(inv, LOCK, "p", "1")), S.render(S.build(inv, LOCK, "p", "1")))

    def test_a_registry_package_without_a_lock_checksum_is_refused(self):
        inv = L.inventory(sample(), ["app"])
        with self.assertRaises(L.LicenceError) as e:
            S.build(inv, LOCK.replace('checksum = "%s"\n' % ("cd" * 32), ""), "p", "1")
        self.assertIn("b", str(e.exception))

    def test_a_package_missing_from_the_lock_is_refused(self):
        inv = L.inventory(sample(), ["app"])
        with self.assertRaises(L.LicenceError):
            S.build(inv, LOCK.replace('name = "a"', 'name = "zzz"'), "p", "1")


class RealWorkspace(unittest.TestCase):
    def test_the_sbom_covers_exactly_the_shipped_closure(self):
        out = subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--filter-platform", "x86_64-unknown-linux-gnu"], cwd=ROOT, capture_output=True, timeout=300)
        if out.returncode != 0:
            self.skipTest("cargo metadata is not available offline here")
        inv = L.inventory(json.loads(out.stdout), ["entropa-gate", "entropa-release"])
        b = S.build(inv, (ROOT / "Cargo.lock").read_text(), "entropa-gate", "0.2.0")
        self.assertEqual(len(b["components"]), len(inv["third_party"]) + len(inv["ours"]))
        self.assertTrue(all("hashes" in c for c in b["components"] if not any(p["name"] == "entropa:workspace" for p in c.get("properties", []))))
        self.assertLess(len(b["components"]), 412, "fewer than the whole lock (it lists every platform)")


if __name__ == "__main__":
    unittest.main()


class Cli(unittest.TestCase):
    def test_runs_as_a_script_under_isolated_mode_from_any_directory(self):
        r = subprocess.run(["python3", "-I", str(ROOT / "tools/release/sbom_shipped.py"), "--help"], cwd="/", capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertIn(b"--product", r.stdout)
