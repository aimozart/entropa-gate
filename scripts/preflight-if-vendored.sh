#!/usr/bin/env bash
# The public-readiness preflight (scripts/public-preflight.sh and its docker-fallback test) needs the vendored preflight in scripts/vendor/, which is private tooling and is not in a public checkout. Present: run both, any failure fails this step. Absent: skip, and say why.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f scripts/vendor/public-repo-preflight.sh ]; then
  scripts/public-preflight.sh
  scripts/tests/public-preflight-shim.sh
else
  echo "skip: the vendored preflight (scripts/vendor/public-repo-preflight.sh) is private tooling and is not part of this checkout; the public-readiness preflight runs where it is present"
fi
