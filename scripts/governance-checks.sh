#!/usr/bin/env bash
# S14b governance checks (docs/CONTROLS-MAP.md gaps T-A, T-B, T-E, T-F, T-G). Exit 0 = clean, 1 = findings, 2 = bad usage or input.
#   wording <file>...                  T-B: "compliant"/"certified" only with an aligned-with / mapped-to / negating context
#   sdk <workspace>                    T-E: no model SDK in a crate except entropa-agent
#   evidence <repo-root>               T-F: every evidence file named in docs/EVIDENCE-INDEX.md exists
#   testchange <repo> <range>          T-G: a commit that changes or removes an existing test file carries a "Test change:" line
#   p0 <file> <from-date>              T-A: every dated line from that date on answers the P0 question ("P0:")
set -uo pipefail
usage() { echo "usage: $0 wording|sdk|evidence|testchange|p0 ..." >&2; exit 2; }
[ $# -ge 1 ] || usage
cmd=$1; shift
found=0
case "$cmd" in
wording)
  [ $# -ge 1 ] || usage
  # earned credential names (exact phrases, one per line, "#" comments) that may use the word; default docs/wording-allow.txt
  allow=${GOV_WORDING_ALLOW:-docs/wording-allow.txt}
  for f in "$@"; do
    [ -f "$f" ] || { echo "no such file: $f" >&2; exit 2; }
    while IFS=: read -r n line; do
      if [ -f "$allow" ] && grep -qFf <(grep -vE '^\s*(#|$)' "$allow") <<<"$line"; then continue; fi
      if grep -qiE '\b(not|never|no|non-?compliant|aligned with|mapped to|unless earned)\b' <<<"$line"; then continue; fi
      echo "$f:$n: claims compliance or certification without an aligned-with / mapped-to context"; found=1
    done < <(grep -niE '\b(compliant|certified|certification)\b' "$f" || true)
  done ;;
sdk)
  [ $# -eq 1 ] && [ -d "$1/crates" ] || { echo "no workspace: ${1:-}" >&2; exit 2; }
  for t in "$1"/crates/*/Cargo.toml; do
    [ -f "$t" ] || continue
    crate=$(basename "$(dirname "$t")")
    [ "$crate" = "entropa-agent" ] && continue
    if grep -qiE '^\s*(aws-sdk-bedrock\w*|google-cloud-aiplatform|async-openai|openai\w*|genai|anthropic\w*|rig-core|llm)\s*=' "$t"; then
      echo "crates/$crate: depends on a model SDK (only entropa-agent may)"; found=1
    fi
  done ;;
evidence)
  [ $# -eq 1 ] && [ -f "$1/docs/EVIDENCE-INDEX.md" ] || { echo "no evidence index under: ${1:-}" >&2; exit 2; }
  while IFS= read -r name; do
    if [ ! -e "$1/docs/evidence/$name" ] && [ ! -e "$1/docs/$name" ] && [ ! -e "$1/$name" ]; then
      echo "docs/EVIDENCE-INDEX.md names $name, which does not exist"; found=1
    fi
  done < <(grep '^|' "$1/docs/EVIDENCE-INDEX.md" | grep -oE '[A-Za-z0-9_./-]+\.(txt|md|py|json)' | sed 's#^docs/evidence/##' | sort -u)
  ;;
testchange)
  [ $# -eq 2 ] && [ -d "$1/.git" -o -f "$1/.git" ] || usage
  while IFS= read -r c; do
    if git -C "$1" diff-tree --no-commit-id --name-status -r "$c" | grep -qE '^[MD][[:space:]]+(crates/[^/]+/)?tests/.*\.rs$'; then
      git -C "$1" log -1 --format=%B "$c" | grep -qE '^Test change:' || { echo "$(git -C "$1" log -1 --format='%h %s' "$c"): changes an existing test without a 'Test change:' line"; found=1; }
    fi
  done < <(git -C "$1" rev-list "$2") ;;
p0)
  [ $# -eq 2 ] && [ -f "$1" ] || { echo "no such file: ${1:-}" >&2; exit 2; }
  while IFS=: read -r n line; do
    d=$(sed -nE 's/^- ([0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/p' <<<"$line")
    [ -n "$d" ] && [[ ! "$d" < "$2" ]] || continue
    grep -q 'P0:' <<<"$line" || { echo "$1:$n: dated $d, no P0 answer"; found=1; }
  done < <(grep -n '^- [0-9]\{4\}-' "$1" || true) ;;
*) usage ;;
esac
exit $found
