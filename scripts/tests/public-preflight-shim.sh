#!/usr/bin/env bash
# S0j follow-up: the preflight must also pass when NO host gitleaks is on PATH (the docker fallback of scripts/public-preflight.sh).
# The reviewer's refreshed preflight passes an ABSOLUTE host path to --config, so the shim has to mount the repository at the same path.
set -uo pipefail
cd "$(dirname "$0")/../.."
dir=$(mktemp -d); trap 'rm -rf "$dir"' EXIT
for b in bash sh env cat sed grep git tar mktemp rm dirname sha256sum docker id printf chmod head tail sort uniq cut tr basename wc find xargs date; do
  p=$(command -v "$b" 2>/dev/null) && ln -s "$p" "$dir/$b"
done
out=$(PATH="$dir" scripts/public-preflight.sh 2>&1); rc=$?
echo "$out" | tail -4
if [ $rc -eq 0 ] && echo "$out" | grep -q "PREFLIGHT PASS" && ! PATH="$dir" command -v gitleaks >/dev/null; then echo "ok   preflight passes through the docker fallback (no host gitleaks on PATH)"; exit 0; fi
echo "FAIL preflight through the docker fallback (rc=$rc)"; exit 1
