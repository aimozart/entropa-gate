#!/usr/bin/env bash
# CI-FIX 2: the vendored preflight (scripts/vendor/) is private tooling and is absent in a public checkout. Then the checks that need it SKIP with a stated reason; when it is present they still run and a wrong hash still FAILS.
# Everything is tried in throwaway copies; the real tree is not touched.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
mk() { # new throwaway repo with the scripts under test
  local d; d="$(mktemp -d "${TMPDIR:-/tmp}/vendopt.XXXXXX")"; mkdir -p "$d/scripts/tests"
  cp "$HERE/scripts/tests/gitignore-baseline.sh" "$d/scripts/tests/"
  [ -f "$HERE/scripts/preflight-if-vendored.sh" ] && cp "$HERE/scripts/preflight-if-vendored.sh" "$d/scripts/"
  cp "$HERE/.gitignore" "$d/.gitignore"; printf 'EXAMPLE=1\n' > "$d/.env.example"
  git -C "$d" init -q; git -C "$d" add .env.example scripts >/dev/null 2>&1; echo "$d"
}
# 1. no vendor directory: the hash check of gitignore-baseline.sh is skipped with a reason, everything else still runs, exit 0
d="$(mk)"; out="$(cd "$d" && scripts/tests/gitignore-baseline.sh 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "1 exit 0 without the vendored preflight" || bad "1 exit $rc without the vendored preflight: $(echo "$out" | grep FAIL | head -2)"
case "$out" in *"skip: the vendored preflight"*) ok "1 the skip is said with its reason";; *) bad "1 no stated skip";; esac
case "$out" in *"ignored: id_rsa"*) ok "1 the ignore checks still ran";; *) bad "1 the ignore checks did not run";; esac
# 2. vendor present with a WRONG hash: still a failure
d="$(mk)"; mkdir -p "$d/scripts/vendor"; echo 'echo preflight' > "$d/scripts/vendor/public-repo-preflight.sh"; echo 'sha256: 0000000000000000000000000000000000000000000000000000000000000000' > "$d/scripts/vendor/public-repo-preflight.sh.source"
out="$(cd "$d" && scripts/tests/gitignore-baseline.sh 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && ok "2 a wrong recorded hash still fails" || bad "2 a wrong recorded hash passed"
# 2b. the vendored script is present but its recorded hash file is missing: that is a failure, not a skip (the pin cannot be checked)
d="$(mk)"; mkdir -p "$d/scripts/vendor"; echo 'echo preflight' > "$d/scripts/vendor/public-repo-preflight.sh"
out="$(cd "$d" && scripts/tests/gitignore-baseline.sh 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && ok "2b the script without its recorded hash fails" || bad "2b the script without its recorded hash passed"
# 3. vendor present with the RIGHT hash: passes
d="$(mk)"; mkdir -p "$d/scripts/vendor"; echo 'echo preflight' > "$d/scripts/vendor/public-repo-preflight.sh"; echo "sha256: $(sha256sum "$d/scripts/vendor/public-repo-preflight.sh" | cut -d' ' -f1)" > "$d/scripts/vendor/public-repo-preflight.sh.source"
out="$(cd "$d" && scripts/tests/gitignore-baseline.sh 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "3 the right recorded hash passes" || bad "3 the right hash failed: $(echo "$out" | grep FAIL | head -2)"
# 4. preflight-if-vendored.sh: absent vendor -> skip with a reason, exit 0, the two preflight scripts are NOT called
d="$(mk)"; for s in public-preflight.sh tests/public-preflight-shim.sh; do printf '#!/usr/bin/env bash\necho CALLED %s >> "%s"\n' "$s" "$d/calls.txt" > "$d/scripts/$s"; chmod +x "$d/scripts/$s"; done
if [ -x "$d/scripts/preflight-if-vendored.sh" ]; then
  out="$(cd "$d" && scripts/preflight-if-vendored.sh 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] && ok "4 absent vendor: exit 0" || bad "4 absent vendor: exit $rc"
  case "$out" in *"skip: the vendored preflight"*) ok "4 the skip is said with its reason";; *) bad "4 no stated skip";; esac
  [ ! -e "$d/calls.txt" ] && ok "4 the preflight scripts were not called" || bad "4 they were called"
  # 5. vendor present: both are called, in order, and a failing one fails the whole
  mkdir -p "$d/scripts/vendor"; echo x > "$d/scripts/vendor/public-repo-preflight.sh"
  (cd "$d" && scripts/preflight-if-vendored.sh >/dev/null 2>&1); rc=$?
  [ "$rc" -eq 0 ] && [ "$(cat "$d/calls.txt" 2>/dev/null | tr '\n' ' ')" = "CALLED public-preflight.sh CALLED tests/public-preflight-shim.sh " ] && ok "5 present vendor: both called in order" || bad "5 present vendor: rc=$rc calls=[$(cat "$d/calls.txt" 2>/dev/null | tr '\n' ' ')]"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$d/scripts/public-preflight.sh"
  (cd "$d" && scripts/preflight-if-vendored.sh >/dev/null 2>&1); rc=$?; [ "$rc" -ne 0 ] && ok "5 a failing preflight fails the step" || bad "5 a failing preflight was ignored"
else bad "4 scripts/preflight-if-vendored.sh does not exist"; fi
exit $fail
