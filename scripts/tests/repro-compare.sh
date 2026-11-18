#!/usr/bin/env bash
# Test of scripts/repro-compare.sh: identical files pass, one changed byte is reported, a missing file fails.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; t=$(mktemp -d "${TMPDIR:-/tmp}/repro-test.XXXXXX")
printf 'synthetic one' > "$t/a"; printf 'synthetic one' > "$t/b"; printf 'synthetic onf' > "$t/c"
out=$("$here/repro-compare.sh" "$t/a" "$t/b") || { echo "FAIL: identical files reported different"; exit 1; }
case "$out" in IDENTICAL*) ;; *) echo "FAIL: $out"; exit 1;; esac
out=$("$here/repro-compare.sh" "$t/a" "$t/c") && { echo "FAIL: a changed byte was not detected"; exit 1; }
case "$out" in DIFFERENT*) ;; *) echo "FAIL: $out"; exit 1;; esac
"$here/repro-compare.sh" "$t/a" "$t/missing" >/dev/null 2>&1 && { echo "FAIL: a missing file passed"; exit 1; }
echo "PASS repro-compare (3 cases); scratch $t"
