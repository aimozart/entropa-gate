"""S2f: the licence inventory (a stage record (not published)). Synthetic metadata only; the real-workspace test runs cargo metadata offline."""
import json
import subprocess
import unittest
from pathlib import Path

from tools.release import licences as L

ROOT = Path(__file__).resolve().parents[3]


def pkg(name, lic, version="1.0.0", source="registry+https://github.com/rust-lang/crates.io-index"):
    return {"id": f"{name} {version}", "name": name, "version": version, "license": lic, "source": source}


def meta(packages, edges, roots):
    """edges: {name: [(dep, kind)]} kind None, 'dev' or 'build'."""
    nodes = []
    ids = {p["name"]: p["id"] for p in packages}
    for p in packages:
        deps = [{"pkg": ids[d], "dep_kinds": [{"kind": k, "target": None}]} for d, k in edges.get(p["name"], [])]
        nodes.append({"id": p["id"], "deps": deps})
    return {"packages": packages, "resolve": {"nodes": nodes}, "workspace_members": [f"{r} 1.0.0" for r in roots]}


class Expr(unittest.TestCase):
    def test_choices(self):
        self.assertEqual(L.evaluate("MIT OR Apache-2.0"), "Apache-2.0")
        self.assertEqual(L.evaluate("MIT/Apache-2.0"), "Apache-2.0")
        self.assertEqual(L.evaluate("Apache-2.0 WITH LLVM-exception OR MIT"), "Apache-2.0 WITH LLVM-exception")
        self.assertEqual(L.evaluate("(MIT OR GPL-3.0) AND ISC"), "ISC AND MIT")
        self.assertEqual(L.evaluate("MIT"), "MIT")
        self.assertEqual(L.evaluate("Unlicense OR MIT"), "MIT")

    def test_refusals(self):
        for bad in ["GPL-3.0", "MIT AND GPL-3.0", "GPL-3.0-only OR AGPL-3.0", "", "   ", "Made-Up-1.0", "(MIT OR ISC", "MIT OR", "MPL-2.0"]:
            with self.assertRaises(L.LicenceError, msg=bad):
                L.evaluate(bad)


class Closure(unittest.TestCase):
    def test_dev_excluded_build_included_workspace_apart(self):
        ps = [pkg("app", "MIT", source=None), pkg("a", "MIT"), pkg("devonly", "GPL-3.0"), pkg("b", "ISC")]
        m = meta(ps, {"app": [("a", None), ("devonly", "dev"), ("b", "build")]}, ["app"])
        r = L.inventory(m, ["app"])
        self.assertEqual([x["name"] for x in r["third_party"]], ["a", "b"])
        self.assertEqual([x["name"] for x in r["ours"]], ["app"])

    def test_transitive(self):
        ps = [pkg("app", "MIT", source=None), pkg("a", "MIT"), pkg("c", "Apache-2.0")]
        m = meta(ps, {"app": [("a", None)], "a": [("c", None)]}, ["app"])
        self.assertEqual([x["name"] for x in L.inventory(m, ["app"])["third_party"]], ["a", "c"])


class Failures(unittest.TestCase):
    def test_no_license_and_gpl_fail_and_name_the_package(self):
        for lic in [None, "GPL-3.0"]:
            ps = [pkg("app", "MIT", source=None), pkg("bad", lic)]
            m = meta(ps, {"app": [("bad", None)]}, ["app"])
            with self.assertRaises(L.LicenceError) as e:
                L.inventory(m, ["app"])
            self.assertIn("bad", str(e.exception))


class Output(unittest.TestCase):
    def test_deterministic_and_sorted(self):
        ps = [pkg("app", "MIT", source=None), pkg("zeta", "MIT"), pkg("alpha", "Apache-2.0 OR MIT", "2.1.0")]
        m = meta(ps, {"app": [("zeta", None), ("alpha", None)]}, ["app"])
        t1 = L.render(L.inventory(m, ["app"])); t2 = L.render(L.inventory(m, ["app"]))
        self.assertEqual(t1, t2)
        self.assertLess(t1.index("alpha 2.1.0"), t1.index("zeta 1.0.0"))
        self.assertIn("alpha 2.1.0  Apache-2.0 OR MIT  ->  Apache-2.0", t1)


class RealWorkspace(unittest.TestCase):
    def test_shipped_packages_pass_the_allowlist(self):
        out = subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--filter-platform", "x86_64-unknown-linux-gnu"],
                             cwd=ROOT, capture_output=True, timeout=300)
        if out.returncode != 0:
            self.skipTest("cargo metadata is not available offline here")
        r = L.inventory(json.loads(out.stdout), ["entropa-gate", "entropa-release"])
        self.assertGreater(len(r["third_party"]), 50)
        self.assertTrue(any(x["name"] == "entropa-gate" for x in r["ours"]))


if __name__ == "__main__":
    unittest.main()
