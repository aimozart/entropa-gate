#!/bin/sh
# SAMPLE target with a PLANTED FLAW: it blocks the synthetic key shape SYNKEY-<16 hex> only in UPPER case, so the lower-case variants slip through.
# Contract: the input is on stdin; the first output line is `allow` or `block`.
in=$(cat)
if printf '%s' "$in" | grep -Eq 'SYNKEY-[0-9A-F]{16}'; then echo block; else echo allow; fi
