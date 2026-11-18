#!/usr/bin/env python3
"""Generates docs/public/RESULTS.md from results.json so the numbers on the public page cannot drift.

make_public_md.py --results results.json --out FILE      exit 0 written, 1 refused (nothing written), 2 usage
"""
import argparse
import json
import os
import sys

EV = "[evidence: docs/results/results.json]"
WORD = {"pass": "passed", "fail": "FAILED", "report_only": "report only", "measured": "measured"}


def refuse(m):
    print("refused: " + m, file=sys.stderr)
    sys.exit(1)


def amount(b):
    if b.get("numerator") is None:
        return str(b["value"])
    return f"{b['numerator']}/{b['denominator']} {b['meaning']}"


def line(r, b):
    return f"- {r['id']}, {b['name']}: {amount(b)} (bar: {b['bar']}) - {WORD[b['result']]}. {EV}"


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--results")
    ap.add_argument("--out")
    try:
        a = ap.parse_args()
    except SystemExit:
        sys.exit(2)
    if not (a.results and a.out):
        print("usage: make_public_md.py --results results.json --out FILE", file=sys.stderr)
        sys.exit(2)
    try:
        d = json.load(open(a.results, encoding="utf-8"))
    except (OSError, ValueError):
        refuse("the data file cannot be read")
    if d.get("schema") != "results-1" or not d.get("rows"):
        refuse("the data is not schema results-1 or has no rows")
    rows, s = d["rows"], d["summary"]
    out = ["# Measured results, failures first", "",
           "Each run below used a set that was run once and is spent: it is never reused, and nothing was tuned after the run. Everything is **tested against** the frozen code of the day. "
           "A failed bar is reported as failed. The data file this page is generated from is checked against the original reports before it is written; the page is regenerated from it, not typed.", "",
           f"{s['rows']} runs, {s['bars']} bars, {s['failed_bars']} failed bars. {EV}", "", "## Failed bars", ""]
    for r in rows:
        for b in r["bars"]:
            if b["result"] == "fail":
                out.append(line(r, b))
    out += ["", "## All runs", ""]
    for r in rows:
        spent = "set spent" if r["set_spent"] else "set not spent"
        size = "size not stated" if r["set_size"] is None else f"{r['set_size']} cases"
        out.append(f"### {r['id']}: {r['title']}")
        out.append("")
        out.append(f"- Date {r['date'] or 'not stated'}, {size}, {spent}. {EV}")
        if r.get("parked"):
            out.append(f"- Parked case study, label \"{r.get('label', 'simulated')}\". {EV}")
        if not r.get("numbers_verified", True):
            out.append(f"- {r['verification_note']} {EV}")
        for f in r["set_flaws"]:
            out.append(f"- Flaw in the set (not counted against the code): {f} {EV}")
        for b in sorted(r["bars"], key=lambda x: {"fail": 0, "report_only": 1, "measured": 1, "pass": 2}[x["result"]]):
            out.append(f"- {b['name']}: {amount(b)} (bar: {b['bar']}) - {WORD[b['result']]}. {EV}")
        out.append("")
    text = "\n".join(out).rstrip() + "\n"
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {a.out}: {len(text)} bytes")


if __name__ == "__main__":
    main()
