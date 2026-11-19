#!/usr/bin/env bash
# CI-FIX 3: scripts/build-admin-ui.sh downloads npm packages (npm ci against the committed lock file). It must SAY so before it does, and --no-network (or ENTROPA_NO_NETWORK=1) must make it refuse to download:
#   present dist -> nothing to do; node_modules present -> build with the container network OFF; neither -> refuse with exit 3 and the reason. Tested with a stub docker that records its arguments.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
tmp="$(mktemp -d "${TMPDIR:-/tmp}/adminnet.XXXXXX")"
mkdir -p "$tmp/bin" "$tmp/repo/scripts" "$tmp/repo/admin-ui"
cp "$HERE/scripts/build-admin-ui.sh" "$tmp/repo/scripts/"
cat > "$tmp/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "DOCKER $*" >> "$STUB_LOG"
STUB
chmod +x "$tmp/bin/docker"
run() { # run <env assignments and args>; prints output; log in $tmp/log
  : > "$tmp/log"; (cd "$tmp/repo" && env -u ENTROPA_NO_NETWORK PATH="$tmp/bin:$PATH" STUB_LOG="$tmp/log" "$@" 2>&1)
}
# 1. default: the banner comes BEFORE the docker call, and says what is downloaded
out="$(run scripts/build-admin-ui.sh)"; rc=$?
case "$out" in *"this step needs the network"*"npm ci"*"package-lock.json"*) ok "1 the banner says it needs the network and what it downloads";; *) bad "1 no banner: ${out:0:200}";; esac
[ -s "$tmp/log" ] && ok "1 then docker runs" || bad "1 docker did not run"
# 2. --no-network with nothing built: refuse, exit 3, docker never called
out="$(run scripts/build-admin-ui.sh --no-network)"; rc=$?
[ "$rc" -eq 3 ] && ok "2 refused with exit 3" || bad "2 exit $rc (wanted 3)"
[ ! -s "$tmp/log" ] && ok "2 docker was not called" || bad "2 docker was called"
case "$out" in *"needs the network"*) ok "2 the refusal says why";; *) bad "2 no reason: ${out:0:200}";; esac
# 3. the environment variable does the same
out="$(run env ENTROPA_NO_NETWORK=1 scripts/build-admin-ui.sh)"; rc=$?
[ "$rc" -eq 3 ] && [ ! -s "$tmp/log" ] && ok "3 ENTROPA_NO_NETWORK=1 refuses too" || bad "3 rc=$rc log=[$(cat "$tmp/log")]"
# 4. node_modules present: build offline (container network off), no npm ci
mkdir -p "$tmp/repo/admin-ui/node_modules"
out="$(run scripts/build-admin-ui.sh --no-network)"; rc=$?
[ "$rc" -eq 0 ] && ok "4 builds from node_modules" || bad "4 exit $rc: ${out:0:200}"
case "$(cat "$tmp/log")" in *"--network none"*) ok "4 the container has no network";; *) bad "4 no --network none: $(cat "$tmp/log")";; esac
case "$(cat "$tmp/log")" in *"npm ci"*) bad "4 npm ci was in the command";; *) ok "4 no npm ci";; esac
case "$(cat "$tmp/log")" in *"npm run build"*) ok "4 npm run build is there";; *) bad "4 no build";; esac
# 5. dist present: nothing to do at all
mkdir -p "$tmp/repo/admin-ui/dist"
out="$(run scripts/build-admin-ui.sh --no-network)"; rc=$?
[ "$rc" -eq 0 ] && [ ! -s "$tmp/log" ] && ok "5 dist present: nothing runs" || bad "5 rc=$rc log=[$(cat "$tmp/log")]"
# 6. an unknown argument is a usage error, not silently ignored
out="$(run scripts/build-admin-ui.sh --bogus)"; rc=$?
[ "$rc" -eq 2 ] && ok "6 unknown option: exit 2" || bad "6 exit $rc"
exit $fail
