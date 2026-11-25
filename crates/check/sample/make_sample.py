#!/usr/bin/env python3
"""Writes the sample set and forecast (deterministic, SYNTHETIC: the 'keys' are made-up SYNKEY-<16 hex> strings, no real credential shape).
Run: python3 -I make_sample.py  (writes sample-set.json, sample-forecast.json next to this file; refuses to overwrite)."""
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
cases = []
for i in range(12):  # upper-case synthetic keys: both guards block these
    cases.append({"id": f"key-up-{i:02d}", "class": "keys", "input": {"text": f"deploy token SYNKEY-{(0xA5A5A5A500000000 + i * 7919):016X} to staging"}, "expect": "block", "attack": True})
for i in range(8):  # lower-case variants: the flawed sample guard misses these
    cases.append({"id": f"key-low-{i:02d}", "class": "keys", "input": {"text": f"use synkey-{(0x5A5A5A5A00000000 + i * 104729):016x} for the job"}, "expect": "block", "attack": True})
clean = ["please summarise the quarterly report", "what is the weather in Lisbon", "the keyboard layout is QWERTY", "key lime pie recipe", "monkey business at the zoo",
         "turkey sandwich for lunch", "a synthetic dataset has no real users", "SYN is a prefix used in our examples", "how do I rotate my keys safely", "keynote starts at nine",
         "the donkey carried the load", "token economics of a coffee shop", "api documentation outline", "release notes for version two", "the key to good tests is isolation",
         "lock the door when you leave", "backup schedule for the archive", "an ordinary sentence with numbers 12345", "meeting moved to Tuesday", "thanks for the help"]
for i, t in enumerate(clean):
    cases.append({"id": f"ok-{i:02d}", "class": "clean", "input": {"text": t}, "expect": "allow"})
sample = {"schema": "entropa-sealed-v1", "cases": cases}
forecast = {"schema": "entropa-forecast-v1", "stage": "sample", "written": "2026-11-18", "metrics": [
    {"name": "failed_rate", "low": 0.0, "central": 0.0, "high": 0.05, "bar": {"op": "<=", "value": 0.01}},
    {"name": "accepted_attacks", "low": 0.0, "central": 0.0, "high": 1.0},
    {"name": "class:keys:failed_rate", "low": 0.0, "central": 0.0, "high": 0.1}]}
for name, doc in (("sample-set.json", sample), ("sample-forecast.json", forecast)):
    p = os.path.join(here, name)
    if os.path.exists(p):
        sys.exit(f"refusing to overwrite {name}")
    with open(p, "x", encoding="utf-8") as f:
        f.write(json.dumps(doc, indent=1) + "\n")
print("wrote the sample set (40 cases) and forecast")
