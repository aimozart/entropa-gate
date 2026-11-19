#!/usr/bin/env bash
# Helpers of the package build. Source this file.
# The licence text of the package: the export asset in the private tree, else the root LICENSE of a public checkout (the same text). A missing or empty file is an error.
pkg1_license_file() {
  local root="$1" f
  for f in "$root/scripts/public-export-assets/LICENSE" "$root/LICENSE"; do
    if [ -s "$f" ]; then echo "$f"; return 0; fi
  done
  echo "pkg1: no licence text found (looked for scripts/public-export-assets/LICENSE and LICENSE under $root)" >&2
  return 1
}
