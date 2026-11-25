#!/usr/bin/env bash
# CI-FIX 8: no silent skips and an honest account of what CI runs. Static checks (the image itself is built by CI, with network):
#  1. the dev image is built FROM a digest-pinned base, installs nodejs and minisign in one apt layer without recommended packages, cleans the apt lists and checks both tools at build time;
#  2. the workflow sets ENTROPA_REQUIRE_TOOLS=1 and passes it into the container, so a missing tool fails a test instead of skipping it;
#  3. TESTING.md and KNOWN-LIMITS say plainly that the CI debug run uses capped property-test case counts, where the full counts come from, and on which machine.
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
D=tools/Dockerfile.dev
grep -qE '^FROM rust:1\.99\.1-bookworm@sha256:[0-9a-f]{64}$' "$D" && ok "1 the base image is pinned by digest" || bad "1 the FROM line is not digest-pinned"
if docker image inspect rust:1.99.1-bookworm >/dev/null 2>&1; then
  have="$(docker image inspect rust:1.99.1-bookworm --format '{{index .RepoDigests 0}}' | sed 's/.*@//')"
  grep -q "@$have" "$D" && ok "1 and the digest is the one of the local image ($have)" || bad "1 the pinned digest differs from the local image ($have)"
else echo "skip: the local base image is absent, the digest is not compared"; fi
grep -qE 'apt-get install -y --no-install-recommends[^&]*\bnodejs\b[^&]*\bminisign\b|apt-get install -y --no-install-recommends[^&]*\bminisign\b[^&]*\bnodejs\b' "$D" && ok "2 nodejs and minisign are installed without recommended packages" || bad "2 no apt install of nodejs and minisign"
grep -q 'apt-get update' "$D" && grep -q 'rm -rf /var/lib/apt/lists' "$D" && ok "2 the apt lists are updated and cleaned in the same layer" || bad "2 apt lists not handled"
grep -qE 'RUN .*node --version.*minisign -v|RUN .*minisign -v.*node --version' "$D" && ok "3 both tools are checked at build time" || bad "3 no build-time check of the tools"
wf=.github/workflows/ci.yml
grep -qE '^  ENTROPA_REQUIRE_TOOLS: "1"$' "$wf" && ok "4 the workflow sets ENTROPA_REQUIRE_TOOLS=1" || bad "4 ENTROPA_REQUIRE_TOOLS=1 is not set in the workflow env"
grep -E '^  IN_DEV_PASS_ENV:' "$wf" | grep -qw ENTROPA_REQUIRE_TOOLS && ok "4 and it is passed into the container" || bad "4 not in IN_DEV_PASS_ENV"
S='The CI debug run uses capped property-test case counts (1,000 to 2,000)'
for f in TESTING.md docs/public/KNOWN-LIMITS.md; do
  grep -qF "$S" "$f" && ok "5 $f carries the case-count sentence" || bad "5 $f lacks the case-count sentence"
done
grep -qE 'cargo test --release' TESTING.md && grep -qiE 'workstation' TESTING.md && grep -qE '20 CPUs' TESTING.md && ok "6 TESTING.md says which command and which machine the release counts come from" || bad "6 TESTING.md does not say where the release counts come from"
exit $fail
