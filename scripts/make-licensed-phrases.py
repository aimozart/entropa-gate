#!/usr/bin/env python3
"""Builds the licensed-phrases file for scripts/check-public-export.sh from the LOCAL licensed sources (the sealed standards store). The output file must be OUTSIDE every repository:
the phrases are licensed text and are never committed. Every window of WORDS consecutive words of every LICENSED clause is written (lower-cased, anything that is not a letter or a digit turned into one space), one per line.
Usage: make-licensed-phrases.py STORE_DIR VERSION OUT_FILE   (OUT_FILE is created with mode 600 and must not exist)"""
import json
import os
import re
import sys

WORDS = 10


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    store, version, out = argv
    src = os.path.join(store, version, "clauses.jsonl")
    if os.path.exists(out):
        print("refused: the output file exists", file=sys.stderr)
        return 2
    here = os.path.dirname(os.path.abspath(out))
    if os.path.exists(os.path.join(here, ".git")):
        print("refused: the output file must not be inside a git working tree", file=sys.stderr)
        return 2
    seen, n = set(), 0
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for line in open(src, encoding="utf-8"):
            c = json.loads(line)
            if str(c.get("tier", "")).upper() != "LICENSED":
                continue
            w = re.sub(r"[^a-z0-9]+", " ", str(c.get("text", "")).lower()).split()
            for i in range(len(w) - WORDS + 1):
                g = " ".join(w[i : i + WORDS])
                if g not in seen:
                    seen.add(g)
                    f.write(g + "\n")
                    n += 1
    print(f"wrote {n} phrases of {WORDS} words to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
