#!/usr/bin/env bash
# Builds admin-ui/dist (embedded by entropa-api) in Docker; Node is not installed on this PC.
# THIS STEP NEEDS THE NETWORK: `npm ci` downloads the packages listed in admin-ui/package-lock.json (integrity-checked against the lock file). The script says so before it starts.
# --no-network (or ENTROPA_NO_NETWORK=1) refuses to download: with admin-ui/dist present it does nothing; with admin-ui/node_modules present it builds with the container network OFF; otherwise it stops with exit 3.
# `npm ci` is retried twice (ENTROPA_NPM_RETRY_DELAY seconds apart, default 5) because the registry sometimes times out
# (EIDLETIMEOUT seen 2026-10-21); every retry is announced as a network retry. The build itself is never retried.
set -euo pipefail
cd "$(dirname "$0")/../admin-ui"
nonet="${ENTROPA_NO_NETWORK:-}"
for a in "$@"; do case "$a" in --no-network) nonet=1 ;; *) echo "usage: build-admin-ui.sh [--no-network]" >&2; exit 2 ;; esac; done
if [ -n "$nonet" ]; then
  [ ! -d dist ] || { echo "build-admin-ui: admin-ui/dist exists; nothing to do (no network)" >&2; exit 0; }
  [ -d node_modules ] || { echo "build-admin-ui: admin-ui/node_modules is missing and the build needs the network (npm ci downloads the packages of package-lock.json); --no-network was given, so nothing was started" >&2; exit 3; }
  echo "build-admin-ui: building from the existing node_modules with the container network OFF" >&2
  exec docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/w -w /w node:22-bookworm sh -c "npm run build"
fi
echo "build-admin-ui: this step needs the network: npm ci downloads the packages listed in admin-ui/package-lock.json (integrity-checked); use --no-network to refuse that" >&2
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
