#!/bin/sh
# SAMPLE target, the flaw fixed: the same shape is blocked in any case.
in=$(cat)
if printf '%s' "$in" | grep -Eiq 'SYNKEY-[0-9A-F]{16}'; then echo block; else echo allow; fi
