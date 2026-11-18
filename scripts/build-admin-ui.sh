#!/usr/bin/env bash
# Builds admin-ui/dist (embedded by entropa-api) in Docker; Node is not installed on this PC.
# `npm ci` is retried twice (ENTROPA_NPM_RETRY_DELAY seconds apart, default 5) because the registry sometimes times out
# (EIDLETIMEOUT seen 2026-10-21); every retry is announced as a network retry. The build itself is never retried.
set -euo pipefail
cd "$(dirname "$0")/../admin-ui"
delay="${ENTROPA_NPM_RETRY_DELAY:-5}"
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/w -w /w node:22-bookworm sh -c "
n=0
until npm ci --no-audit --no-fund; do
  n=\$((n + 1))
  [ \"\$n\" -le 2 ] || { echo 'build-admin-ui: npm ci failed 3 times, giving up' >&2; exit 1; }
  echo \"build-admin-ui: npm ci failed (possibly a registry network timeout); network retry \$n of 2 in ${delay}s\" >&2
  sleep ${delay}
done
npm run build"
