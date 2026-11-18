#!/usr/bin/env bash
# The one canonical verification entrypoint for this repo — named obviously so a human
# or automated reviewer finds it without piecing together scattered docs. Runs the exact
# same checks as the pre-commit hook and this repo's own CI (scripts/ci.sh); this is a
# thin, permanently-stable alias so README.md/TESTING.md/SECURITY.md/the project rules/
# docs/VERIFY.md can all point at one name that never needs to change even if the
# underlying check list grows.
set -euo pipefail
exec "$(dirname "${BASH_SOURCE[0]}")/ci.sh"
