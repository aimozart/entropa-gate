#!/usr/bin/env bash
# CI-FIX 2: the .gitignore that the exporter writes (scripts/public-export-assets/.gitignore) must keep EVERY secret-file pattern of the baseline (it is the private .gitignore plus the process-file lines, never a replacement): checked with git itself in a throwaway repository,
# and no line of the private baseline block may be missing from it. In a public checkout the export tooling is not there: the test says so and skips.
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
A=scripts/public-export-assets/.gitignore
if [ ! -f "$A" ]; then echo "skip: $A is export tooling and is not part of this checkout (the exported .gitignore is checked by scripts/tests/gitignore-baseline.sh)"; exit 0; fi
T="$(mktemp -d "${TMPDIR:-/tmp}/pubgi.XXXXXX")"; git -C "$T" init -q; cp "$A" "$T/.gitignore"; printf 'EXAMPLE=1\n' > "$T/.env.example"
for p in .env .env.local .env.production id_rsa id_ed25519 server.pem server.key cert.p12 cert.pfx keystore.jks .aws/credentials credentials.json service-account.json service-account-prod.json .claude/settings.local.json .claude/hook-audit.jsonl terraform.tfstate terraform.tfstate.backup .terraform/x secrets/x .npmrc .netrc node_modules/x target/x .DS_Store debug.log vault.gpg admin-ui/dist/index.html admin-ui/node_modules/x/y; do
  if git -C "$T" check-ignore -q "$p"; then ok "ignored: $p"; else bad "NOT ignored: $p"; fi
done
if git -C "$T" check-ignore -q .env.example; then bad ".env.example is ignored"; else ok ".env.example is not ignored"; fi
dups=$(grep -vE '^\s*(#|$)' "$A" | sort | uniq -d); if [ -z "$dups" ]; then ok "no duplicate line"; else bad "duplicates: $dups"; fi
# every pattern line of the private baseline block is in the exported file
start=$(grep -n '^# --- public-repo baseline' .gitignore | head -1 | cut -d: -f1)
missing=0
if [ -n "$start" ]; then
  while IFS= read -r l; do grep -qxF -- "$l" "$A" || { bad "missing from the exported .gitignore: $l"; missing=1; }; done < <(tail -n +"$((start+1))" .gitignore | grep -vE '^\s*(#|$)')
  [ "$missing" -eq 0 ] && ok "every pattern of the private baseline block is in the exported .gitignore"
else bad "the private .gitignore has no baseline block"; fi
exit $fail
