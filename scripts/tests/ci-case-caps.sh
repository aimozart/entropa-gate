#!/usr/bin/env bash
# CI-FIX 7: property tests read their case count from an environment variable (AT1_CASES, H13_CASES, ...; 100,000 by default). In the debug CI run on a 4-CPU runner those defaults take many hours (one binary took over 30 minutes at 10,000 cases).
# Every such variable found in the test sources must therefore be set in the workflow's top-level env block AND be listed in IN_DEV_PASS_ENV there, so that it reaches the container. The full-size runs are the release builds, not the debug CI run.
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
vars="$(grep -rhoE 'env::var\("[A-Z0-9_]+_CASES"\)' crates --include=*.rs | sed -E 's/.*\("([A-Z0-9_]+)"\)/\1/' | sort -u)"
[ -n "$vars" ] && ok "found the case variables in the sources: $(echo $vars | tr '\n' ' ')" || { bad "no *_CASES variable found in the sources (the search itself is broken)"; exit 1; }
wf=.github/workflows/ci.yml
top="$(python3 - "$wf" <<'PY'
import sys,re
t=open(sys.argv[1]).read().split('\n')
out=[];on=False
for l in t:
    if re.match(r'^env:\s*$',l): on=True; continue
    if on:
        if re.match(r'^\S',l): break
        out.append(l)
print('\n'.join(out))
PY
)"
[ -n "$top" ] && ok "$wf has a top-level env block" || bad "$wf has no top-level env block"
for v in $vars; do
  echo "$top" | grep -qE "^\s+$v:\s*\"?[0-9]+\"?\s*$" && ok "$v is capped in the workflow env" || bad "$v is not capped in the workflow env"
  echo "$top" | grep -E "^\s+IN_DEV_PASS_ENV:" | grep -qw "$v" && ok "$v is passed into the container (IN_DEV_PASS_ENV)" || bad "$v is not listed in IN_DEV_PASS_ENV"
done
# a cap must be a real reduction: at most 10,000 cases
for v in $vars; do
  n="$(echo "$top" | sed -nE "s/^\s+$v:\s*\"?([0-9]+)\"?\s*$/\1/p" | head -1)"
  [ -n "$n" ] && [ "$n" -le 10000 ] && ok "$v=$n is a reduction" || bad "$v is not a number up to 10000 ($n)"
done
exit $fail
