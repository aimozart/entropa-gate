#!/usr/bin/env bash
# S12a (the reviewer's finding): a transient npm registry timeout must not fail the gate. scripts/build-admin-ui.sh retries `npm ci`
# up to two more times and says so. Tested with a stub `docker` that runs the inner shell command locally against a fake `npm`.
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
# stub docker: the last argument is the `sh -c` command line of the real script; run it here
cat > "$tmp/bin/docker" <<'STUB'
#!/usr/bin/env bash
eval "set -- \"\${@: -1}\""
exec sh -c "$1"
STUB
# fake npm: `ci` fails the first $FAIL_CI times (as a registry timeout would), `run build` always works
cat > "$tmp/bin/npm" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = ci ]; then
  n=$(cat "$NPM_COUNT" 2>/dev/null || echo 0); echo $((n + 1)) > "$NPM_COUNT"
  [ "$n" -lt "$FAIL_CI" ] && { echo "npm error code EIDLETIMEOUT" >&2; exit 1; }
  exit 0
fi
[ "$1 $2" = "run build" ] && { echo built >> "$NPM_COUNT.build"; exit 0; }
exit 2
STUB
chmod +x "$tmp/bin/docker" "$tmp/bin/npm"
try() { # try <failures> -> prints output, sets $rc and the attempt count
  rm -f "$tmp/count" "$tmp/count.build"
  # Test change (CI-FIX 3): the caller's ENTROPA_NO_NETWORK must not leak into this test (a clean-clone check runs with it set)
  out="$(env -u ENTROPA_NO_NETWORK PATH="$tmp/bin:$PATH" NPM_COUNT="$tmp/count" FAIL_CI="$1" ENTROPA_NPM_RETRY_DELAY=0 scripts/build-admin-ui.sh 2>&1)"; rc=$?
  attempts=$(cat "$tmp/count" 2>/dev/null || echo 0); built=$(cat "$tmp/count.build" 2>/dev/null | wc -l)
}
try 0; [ "$rc" -eq 0 ] && [ "$attempts" -eq 1 ] && [ "$built" -eq 1 ] && ok "no failure: one npm ci, then the build" || bad "no failure (rc=$rc attempts=$attempts built=$built)"
try 1; [ "$rc" -eq 0 ] && [ "$attempts" -eq 2 ] && [ "$built" -eq 1 ] && ok "one timeout: retried once, build runs" || bad "one timeout (rc=$rc attempts=$attempts built=$built)"
case "$out" in *"network retry 1 of 2"*) ok "the retry is announced as a network retry";; *) bad "retry not announced: $out";; esac
try 2; [ "$rc" -eq 0 ] && [ "$attempts" -eq 3 ] && [ "$built" -eq 1 ] && ok "two timeouts: retried twice, build runs" || bad "two timeouts (rc=$rc attempts=$attempts built=$built)"
try 3; [ "$rc" -ne 0 ] && [ "$attempts" -eq 3 ] && [ "$built" -eq 0 ] && ok "three timeouts: gives up after 3 attempts and fails, no build" || bad "three timeouts (rc=$rc attempts=$attempts built=$built)"
exit $fail
