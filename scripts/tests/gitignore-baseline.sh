#!/usr/bin/env bash
# S0j: the public .gitignore baseline. Every sample path the preflight probes must be ignored (git check-ignore), .env.example must
# stay tracked and un-ignored, .gitignore must hold no duplicate line, and the vendored preflight must match its recorded hash.
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
for p in .env .env.local .env.production id_rsa id_ed25519 server.pem server.key cert.p12 cert.pfx keystore.jks .aws/credentials \
         credentials.json service-account.json service-account-prod.json .claude/settings.local.json .claude/hook-audit.jsonl \
         terraform.tfstate terraform.tfstate.backup .terraform/x secrets/x .npmrc .netrc node_modules/x target/x .DS_Store debug.log vault.gpg; do
  if git check-ignore -q "$p"; then ok "ignored: $p"; else bad "NOT ignored: $p"; fi
done
if git ls-files --error-unmatch .env.example >/dev/null 2>&1; then ok ".env.example is tracked"; else bad ".env.example is not tracked"; fi
if git check-ignore -q .env.example; then bad ".env.example is ignored"; else ok ".env.example is not ignored"; fi
dups=$(grep -vE '^\s*(#|$)' .gitignore | sort | uniq -d)
if [ -z "$dups" ]; then ok ".gitignore has no duplicate line"; else bad ".gitignore duplicates: $dups"; fi
tracked_ignored=$(git ls-files -ci --exclude-standard | grep -v "/fuzz/corpus/" | head -5)
if [ -z "$tracked_ignored" ]; then ok "no tracked file (outside the fuzz corpora) is covered by an ignore pattern"; else bad "tracked but ignored: $tracked_ignored"; fi
want=$(sed -n 's/^sha256: //p' scripts/vendor/public-repo-preflight.sh.source)
have=$(sha256sum scripts/vendor/public-repo-preflight.sh | cut -d' ' -f1)
if [ -n "$want" ] && [ "$want" = "$have" ]; then ok "the vendored preflight matches its recorded hash"; else bad "the vendored preflight does not match its recorded hash"; fi
exit $fail
