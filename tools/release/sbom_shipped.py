"""SBOM (CycloneDX 1.5) of the SHIPPED closure: exactly the packages that go into the binaries (a stage record (not published)), not the whole lock.

sbom_shipped.py [--roots entropa-gate,entropa-release] --product P --version V --out FILE
Deterministic: sorted components, no timestamp, no random serial. Registry packages carry the SHA-256 checksum from Cargo.lock and their license expression; our own workspace
crates are marked `entropa:workspace`. A registry package without a lock checksum, or absent from the lock, is refused.
"""
import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # so it runs as a script under -I from any directory
from tools.release import licences as L  # noqa: E402


def build(inv, lock_text, product, version):
    lock = {}
    for p in tomllib.loads(lock_text).get("package", []):
        lock[(p["name"], p["version"])] = p.get("checksum")
    comps = []
    for x in inv["third_party"]:
        key = (x["name"], x["version"])
        if key not in lock:
            raise L.LicenceError(f"{x['name']} {x['version']}: not in Cargo.lock")
        if not lock[key]:
            raise L.LicenceError(f"{x['name']} {x['version']}: no checksum in Cargo.lock")
        comps.append({"type": "library", "name": x["name"], "version": x["version"], "purl": f"pkg:cargo/{x['name']}@{x['version']}",
                      "hashes": [{"alg": "SHA-256", "content": lock[key]}], "licenses": [{"expression": x["license"]}]})
    for x in inv["ours"]:
        c = {"type": "library", "name": x["name"], "version": x["version"], "purl": f"pkg:cargo/{x['name']}@{x['version']}",
             "properties": [{"name": "entropa:workspace", "value": "true"}]}
        if x.get("license"):
            c["licenses"] = [{"expression": x["license"]}]
        comps.append(c)
    comps.sort(key=lambda c: (c["name"], c["version"]))
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": product, "version": version}}, "components": comps}


def render(bom):
    return json.dumps(bom, indent=1, sort_keys=True) + "\n"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--roots", default="entropa-gate,entropa-release")
    ap.add_argument("--product", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    r = subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--filter-platform", "x86_64-unknown-linux-gnu"], capture_output=True)
    if r.returncode != 0:
        print("cargo metadata failed", file=sys.stderr)
        return 1
    try:
        inv = L.inventory(json.loads(r.stdout), a.roots.split(","))
        with open("Cargo.lock", encoding="utf-8") as f:
            text = render(build(inv, f.read(), a.product, a.version))
    except (L.LicenceError, OSError) as e:
        print(f"sbom failed: {e}", file=sys.stderr)
        return 1
    with open(a.out, "x", encoding="utf-8") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
