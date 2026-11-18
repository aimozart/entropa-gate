#!/usr/bin/env bash
# Line coverage with cargo-llvm-cov. FLOOR (percent, default 0 = report only) fails the run when below.
set -euo pipefail
source "$(dirname "$0")/lib-docker.sh"
[ -d "$ROOT/admin-ui/dist" ] || "$ROOT/scripts/build-admin-ui.sh"
in_dev cargo llvm-cov --workspace --locked --summary-only --fail-under-lines "${FLOOR:-0}"
