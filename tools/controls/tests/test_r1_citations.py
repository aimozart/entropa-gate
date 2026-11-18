"""R1 task 5, host side: every E1 register quote (at most 25 words) is found inside the sealed R1 clause that the register row cites. This ties
the two stages together. It needs the sealed store (outside every repo, licensed text) and FAILS when it is missing, like the E1 quote tests;
set E1_ALLOW_MISSING_SOURCES=1 to skip it on a machine without the store."""
import json
import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
STORE = Path(os.environ.get("ENTROPA_STANDARDS_STORE") or Path.home() / ".cache" / "build" / "standards-store")


def compact(t: str) -> str:
    return re.sub(r"[\s\-]+", "", t.replace("’", "'").replace("“", '"').replace("”", '"'))


class RegisterQuotesInSealedCorpus(unittest.TestCase):
    def test_each_register_quote_is_inside_its_cited_clause(self):
        cites = json.loads((ROOT / "compliance" / "citations.json").read_text())
        clauses_file = STORE / cites["corpus_version"] / "clauses.jsonl"
        if not clauses_file.exists():
            if os.environ.get("E1_ALLOW_MISSING_SOURCES") == "1":
                self.skipTest("the sealed store is not on this machine")
            self.fail(f"the sealed store is missing: {clauses_file}")
        text = {(c["standard"], c["id"]): c["text"] for c in map(json.loads, clauses_file.read_text().splitlines()) if c}
        reg = {r["id"]: r for r in json.loads((ROOT / "compliance" / "controls-register.json").read_text())["rows"]}
        bad = []
        for row in cites["register_rows"]:
            clause = text.get((row["standard"], row["clause"]))
            if clause is None or compact(reg[row["register_id"]]["quote"]) not in compact(clause):
                bad.append(row["register_id"])
        self.assertEqual(bad, [], "register quotes not found in their cited sealed clause")


if __name__ == "__main__":
    unittest.main()
