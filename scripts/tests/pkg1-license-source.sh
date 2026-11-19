#!/usr/bin/env bash
# RELEASE-FIX: pkg1-build.sh must find the licence text in a PUBLIC checkout too (there, scripts/public-export-assets/ does not exist and the root LICENSE is the same text). The choice is made by pkg1_license_file in scripts/lib-pkg1.sh; tried in throwaway trees.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
[ -f "$HERE/scripts/lib-pkg1.sh" ] || { bad "scripts/lib-pkg1.sh does not exist"; exit 1; }
source "$HERE/scripts/lib-pkg1.sh"
t() { mktemp -d "${TMPDIR:-/tmp}/pkg1lic.XXXXXX"; }
d="$(t)"; mkdir -p "$d/scripts/public-export-assets"; echo public-text > "$d/scripts/public-export-assets/LICENSE"; echo root-text > "$d/LICENSE"
[ "$(pkg1_license_file "$d")" = "$d/scripts/public-export-assets/LICENSE" ] && ok "1 private tree: the export asset is used" || bad "1 wrong file: $(pkg1_license_file "$d")"
d="$(t)"; echo root-text > "$d/LICENSE"
[ "$(pkg1_license_file "$d")" = "$d/LICENSE" ] && ok "2 public checkout: the root LICENSE is used" || bad "2 wrong file: $(pkg1_license_file "$d")"
d="$(t)"; out="$(pkg1_license_file "$d" 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && ok "3 no licence text anywhere: it fails" || bad "3 it did not fail"
case "$out" in *"no licence"*) ok "3 and says why";; *) bad "3 no reason: $out";; esac
d="$(t)"; : > "$d/LICENSE"; pkg1_license_file "$d" >/dev/null 2>&1 && bad "4 an empty LICENSE was accepted" || ok "4 an empty LICENSE is refused"
# the build script uses the helper and no longer copies the private path directly
grep -q 'pkg1_license_file' "$HERE/scripts/pkg1-build.sh" && ok "5 pkg1-build.sh uses the helper" || bad "5 pkg1-build.sh does not use the helper"
grep -q 'cp scripts/public-export-assets/LICENSE' "$HERE/scripts/pkg1-build.sh" && bad "6 pkg1-build.sh still copies the private path directly" || ok "6 no direct copy of the private path"
exit $fail
