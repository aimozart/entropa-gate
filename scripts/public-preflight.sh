#!/usr/bin/env bash
# Public-readiness preflight (S0j): runs the reviewer's read-only preflight (vendored verbatim in scripts/vendor/, hash pinned)
# over this repository: .gitignore baseline samples, tracked sensitive-looking files, gitleaks over the tree and the full
# history. Prints PREFLIGHT PASS or PREFLIGHT FAIL, never a secret. If gitleaks is not on PATH, the pinned Docker image of
# scripts/secret-scan.sh is used through a temporary shim, so the step needs docker only (like check.sh).
set -euo pipefail
cd "$(dirname "$0")/.."
want=$(sed -n 's/^sha256: //p' scripts/vendor/public-repo-preflight.sh.source)
have=$(sha256sum scripts/vendor/public-repo-preflight.sh | cut -d' ' -f1)
[ "$want" = "$have" ] || { echo "public-preflight: the vendored preflight does not match its recorded hash" >&2; exit 2; }
if ! command -v gitleaks >/dev/null 2>&1; then
  image=$(sed -n 's/^IMAGE="\(.*\)"$/\1/p' scripts/secret-scan.sh)
  shim=$(mktemp -d); trap 'rm -rf "$shim"' EXIT
  # the vendored preflight passes an ABSOLUTE host path to --config, so the repository is also mounted (read-only) at its own path
  root=$(pwd)
  printf '#!/usr/bin/env bash\nexec docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/repo -w /repo -v "%s":"%s":ro %s "$@"\n' "$root" "$root" "$image" > "$shim/gitleaks"
  chmod +x "$shim/gitleaks"; export PATH="$shim:$PATH"
fi
exec bash scripts/vendor/public-repo-preflight.sh .
