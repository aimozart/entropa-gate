#!/usr/bin/env bash
# Checks the public documents (docs/public): every claim bullet carries [evidence: path, ...] pointers; each pointer is a repo-relative TRACKED file or directory;
# no email-shaped text; no banned words (secure, compliant, certified); README.md says "tested against". Exit 0 ok, 1 problems (all printed), 2 usage.
# Usage (inside the repository): scripts/check-public-docs.sh [DIR]   (default docs/public). GLOSSARY.md and README.md are not claim lists.
set -uo pipefail
dir="${1:-docs/public}"
git rev-parse --show-toplevel >/dev/null 2>&1 || { echo "not inside a git repository" >&2; exit 2; }
cd "$(git rev-parse --show-toplevel)" || exit 2
mapfile -t docs < <(git ls-files -- "$dir" | grep -E '\.md$')
[ ${#docs[@]} -gt 0 ] || { echo "problem: no markdown files tracked in $dir" >&2; exit 1; }
problems=0; say() { echo "problem: $*" >&2; problems=$((problems+1)); }
for f in "${docs[@]}"; do
  base=$(basename "$f")
  if [ "$base" != README.md ] && [ "$base" != GLOSSARY.md ]; then
    while IFS=: read -r n line; do say "$f:$n: claim bullet has no evidence pointer"; done < <(grep -nE '^[-*] ' "$f" | grep -v '\[evidence:')
  fi
  while IFS= read -r ptrs; do
    IFS=',' read -ra items <<< "$ptrs"
    for it in "${items[@]}"; do
      p=$(echo "$it" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/#.*$//')
      [ -n "$p" ] || { say "$f: empty evidence pointer"; continue; }
      case "$p" in /*|../*|*/../*|..) say "$f: pointer is not repo-relative: $p"; continue;; esac
      [ -n "$(git ls-files -- "$p" | head -1)" ] || say "$f: pointer is not a tracked file: $p"
    done
  done < <(grep -oE '\[evidence:[^]]*\]' "$f" | sed -E 's/^\[evidence:[[:space:]]*//; s/\]$//')
  grep -nE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$f" | grep -v '@example\.invalid' | while IFS= read -r l; do echo "problem: $f: email-shaped text: ${l:0:80}" >&2; done
  if grep -nE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$f" | grep -qv '@example\.invalid'; then problems=$((problems+1)); fi
  if sed 's/HITRUST secure development and maintenance//g' "$f" | grep -qiE '\b(secure|compliant|certified)\b'; then say "$f: banned word (secure, compliant or certified)"; fi
done
grep -qi 'tested against' "$dir/README.md" 2>/dev/null || say "$dir/README.md must say 'tested against'"
[ $problems -eq 0 ] || { echo "$problems problem(s)" >&2; exit 1; }
echo "ok: ${#docs[@]} files, all pointers tracked"
