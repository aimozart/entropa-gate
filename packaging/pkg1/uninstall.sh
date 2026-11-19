#!/bin/sh
# Removes exactly what install.sh installed, as listed in its install record. Never touches keys, ledgers or any node directory.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
record="$here/install-record"
[ -f "$record" ] || { echo "uninstall refused: no install record next to this script" >&2; exit 1; }
prefix=$(sed -n 's/^prefix //p' "$record" | head -1)
case "$prefix" in /*) ;; *) echo "uninstall refused: the record has no prefix" >&2; exit 1 ;; esac
sed -n 's/^file //p' "$record" | while IFS= read -r f; do
  case "$f" in "$prefix"/*) [ "$f" = "$here/uninstall.sh" ] || rm -f "$f" ;; *) echo "skipping $f (outside the prefix)" >&2 ;; esac
done
dirs=$(sed -n 's/^dir //p' "$record" | LC_ALL=C sort -r)
rm -f "$record"
rm -f "$here/uninstall.sh"
for d in $dirs; do case "$d" in "$prefix"|"$prefix"/*) rmdir "$d" 2>/dev/null || true ;; esac; done
echo "entropa-gate removed from $prefix (your keys and ledgers were not touched)"
