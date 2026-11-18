#!/usr/bin/env bash
# Compare two files byte for byte by sha256; prints "IDENTICAL <sha>" (exit 0) or "DIFFERENT <sha1> <sha2>" (exit 1).
set -euo pipefail
a=$(sha256sum "$1" | cut -d' ' -f1); b=$(sha256sum "$2" | cut -d' ' -f1)
if [ "$a" = "$b" ]; then echo "IDENTICAL $a"; else echo "DIFFERENT $a $b"; exit 1; fi
