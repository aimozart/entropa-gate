#!/usr/bin/env bash
# Alias for verify-entropa-persistence.sh - the real, read-only smoke check against
# the live deployed service (health, height climbing, full Chain::verify()).
set -euo pipefail
exec "$(dirname "$0")/verify-entropa-persistence.sh"
