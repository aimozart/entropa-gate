#!/usr/bin/env bash
# Fails if any page of the retired site still links to the removed /signup flow (S0c1 deleted it).
set -euo pipefail
cd "$(dirname "$0")/.."
if hits="$(grep -rnE '/signup|api/signup' website --include='*.html' --include='*.xml' --include='*.txt')"; then
  echo "dead /signup references found:"; echo "$hits"; exit 1
fi
echo "site links ok: no /signup references under website/"
