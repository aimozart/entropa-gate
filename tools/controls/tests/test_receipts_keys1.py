"""KEYS1: the receipt node wrapper must not re-initialise a node that already has per-ledger keys (init refuses an initialised directory)."""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tools.controls.receipts import Node


def stub(path: Path, log: Path) -> Path:
    path.write_text(f"#!/bin/sh\necho \"$1\" >> {log}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class InitTests(unittest.TestCase):
    def run_init(self, files):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            d = t / "node"
            d.mkdir()
            for f in files:
                (d / f).write_text("00\n")
            log = t / "calls.txt"
            Node(d, stub(t / "bin", log)).init()
            return log.read_text().split() if log.exists() else []

    def test_empty_directory_is_initialised(self):
        self.assertEqual(self.run_init([]), ["init"])

    def test_legacy_key_means_already_initialised(self):
        self.assertEqual(self.run_init(["platinum.key"]), [])

    def test_per_ledger_keys_mean_already_initialised(self):
        self.assertEqual(self.run_init(["decisions.key", "evidence.key"]), [])
        self.assertEqual(self.run_init(["evidence.key"]), [])


if __name__ == "__main__":
    unittest.main()
