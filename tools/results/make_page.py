#!/usr/bin/env python3
"""Static results page (a stage record (not published)).

make_page.py --results results.json --out DIR      exit 0 written, 1 refused (nothing written), 2 usage
Validates the data, then writes index.html, style.css, app.js, robots.txt, sitemap.xml, llms.txt and data/results.json (with < > & escaped). DIR must not exist.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = ("pass", "fail", "report_only", "measured")


def refuse(msg):
    print("refused: " + msg, file=sys.stderr)
    sys.exit(1)


def validate(d):
    if not isinstance(d, dict) or d.get("schema") != "results-1":
        refuse("the data is not schema results-1")
    rows = d.get("rows")
    if not isinstance(rows, list) or not rows:
        refuse("the data has no rows")
    n_bars = n_failed = 0
    for r in rows:
        for k in ("id", "title", "bars", "sources", "set_flaws", "set_spent"):
            if k not in r:
                refuse(f"row {r.get('id', '?')} lacks {k}")
        if r["set_spent"] is not True:
            refuse(f"row {r['id']}: a set that is not spent must not be shown as a result")
        for b in r["bars"]:
            if b.get("result") not in RESULTS or "name" not in b or "bar" not in b:
                refuse(f"row {r['id']}: a bar is malformed")
            n_bars += 1
            n_failed += b["result"] == "fail"
    # newest first (a stage record (not published)); a row without a date goes last. The tie rule for equal dates belongs to the generator: the page checks the dates only.
    for a, b in zip(rows, rows[1:]):
        da, db = a.get("date"), b.get("date")
        if (da is None and db is not None) or (da is not None and db is not None and da < db):
            refuse(f"the rows are not in order (newest first): {a['id']} before {b['id']}")
    s = d.get("summary", {})
    if (s.get("rows"), s.get("bars"), s.get("failed_bars")) != (len(rows), n_bars, n_failed):
        refuse("the summary does not match the rows")


def safe_json(d):
    t = json.dumps(d, indent=1, ensure_ascii=False)
    return t.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") + "\n"


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--results")
    ap.add_argument("--out")
    try:
        a = ap.parse_args()
    except SystemExit:
        sys.exit(2)
    if not (a.results and a.out):
        print("usage: make_page.py --results results.json --out DIR", file=sys.stderr)
        sys.exit(2)
    if os.path.exists(a.out):
        refuse("the output directory exists")
    try:
        data = json.load(open(a.results, encoding="utf-8"))
    except (OSError, ValueError):
        refuse("the data file cannot be read")
    validate(data)
    out = []
    for name in ("index.html", "style.css", "app.js", "robots.txt", "sitemap.xml", "llms.txt"):
        out.append((name, open(os.path.join(HERE, "assets", name), "rb").read()))
    out.append(("data/results.json", safe_json(data).encode("utf-8")))
    os.makedirs(os.path.join(a.out, "data"))
    for name, b in out:
        with open(os.path.join(a.out, name), "wb") as f:
            f.write(b)
    print(f"wrote {a.out}: {len(out)} files, {sum(len(b) for _, b in out)} bytes")


if __name__ == "__main__":
    main()
