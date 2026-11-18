#!/usr/bin/env bash
# gitleaks over the working tree and the full git history, in Docker (image pinned by digest, v8.30.1).
# Findings are printed redacted (rule, file, line only). Exit 1 if any finding is not allowlisted in
# .gitleaks.toml (every allowlist entry there carries its reason).
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
run() { docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/repo -w /repo "$IMAGE" "$@"; }
rc=0
echo "== working tree"; run dir . --config .gitleaks.toml --redact --no-banner --verbose --max-target-megabytes 5 || rc=1
echo "== full history"; run git . --config .gitleaks.toml --redact --no-banner --verbose || rc=1
[ "$rc" -eq 0 ] && echo "secret scan clean" || echo "secret scan found unallowlisted findings (values redacted above)"
exit "$rc"
