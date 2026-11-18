#!/usr/bin/env bash
# Tests for scripts/check-public-docs.sh: every claim bullet carries a checkable evidence pointer; pointers must be tracked files; wording and email rules.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; tool="$here/check-public-docs.sh"
base=$(mktemp -d "${TMPDIR:-/tmp}/cpd-test.XXXXXX"); pass=0; fail=0
ok(){ pass=$((pass+1)); echo "ok   $1"; }; bad(){ fail=$((fail+1)); echo "FAIL $1"; }
fixture(){ local d="$base/$1"; mkdir -p "$d/docs/public" "$d/docs/evidence"; cd "$d" || exit 1; git init -q . 2>/dev/null; git config user.email t@example.invalid; git config user.name t
  printf 'evidence one\n' > docs/evidence/one.txt
  printf '# Index\nEverything here is tested against the code of the day.\n' > docs/public/README.md
  printf '# Terms\n- ledger: an append-only log\n' > docs/public/GLOSSARY.md
  printf '# Arch\n- the log is append-only [evidence: docs/evidence/one.txt]\n- a second claim [evidence: docs/evidence/one.txt, docs/evidence/one.txt#section]\n' > docs/public/ARCH.md
  git add -A && git commit -q -m f; echo "$d"; }
run(){ err=$( cd "$1" && "$tool" docs/public 2>&1 >/dev/null ); rc=$?; }
r=$(fixture good); run "$r"; if [ $rc -eq 0 ]; then ok good-passes; else bad "good rc=$rc $err"; fi
r=$(fixture noev); printf -- '- a claim without a pointer\n' >> "$r/docs/public/ARCH.md"; (cd "$r" && git commit -qam x); run "$r"
if [ $rc -eq 1 ] && echo "$err" | grep -qi "no evidence pointer"; then ok bullet-without-evidence; else bad "noev rc=$rc $err"; fi
r=$(fixture miss); printf -- '- claim [evidence: docs/evidence/nope.txt]\n' >> "$r/docs/public/ARCH.md"; (cd "$r" && git commit -qam x); run "$r"
if [ $rc -eq 1 ] && echo "$err" | grep -qi "not a tracked file"; then ok pointer-to-missing-file; else bad "miss rc=$rc $err"; fi
r=$(fixture untr); echo x > "$r/docs/evidence/untracked.txt"; printf -- '- claim [evidence: docs/evidence/untracked.txt]\n' >> "$r/docs/public/ARCH.md"; (cd "$r" && git commit -qam x); run "$r"
if [ $rc -eq 1 ] && echo "$err" | grep -qi "not a tracked file"; then ok pointer-to-untracked-file; else bad "untr rc=$rc $err"; fi
r=$(fixture esc); printf -- '- claim [evidence: ../outside.txt]\n- claim [evidence: /etc/passwd]\n' >> "$r/docs/public/ARCH.md"; (cd "$r" && git commit -qam x); run "$r"
if [ $rc -eq 1 ] && echo "$err" | grep -qi "repo-relative"; then ok pointer-escape; else bad "esc rc=$rc $err"; fi
r=$(fixture mail); printf 'contact someone@example.com\n' >> "$r/docs/public/GLOSSARY.md"; (cd "$r" && git commit -qam x); run "$r"
if [ $rc -eq 1 ] && echo "$err" | grep -qi "email"; then ok email; else bad "mail rc=$rc $err"; fi
r=$(fixture word); printf 'This is secure.\n' >> "$r/docs/public/GLOSSARY.md"; (cd "$r" && git commit -qam x); run "$r"
if [ $rc -eq 1 ] && echo "$err" | grep -qi "banned word"; then ok banned-word; else bad "word rc=$rc $err"; fi
r=$(fixture label); printf '# Index\nplain\n' > "$r/docs/public/README.md"; (cd "$r" && git commit -qam x); run "$r"
if [ $rc -eq 1 ] && echo "$err" | grep -qi "tested against"; then ok readme-needs-the-wording; else bad "label rc=$rc $err"; fi
r=$(fixture empty); mkdir -p "$r/docs/public2"; err=$( cd "$r" && "$tool" docs/public2 2>&1 >/dev/null ); rc=$?
if [ $rc -eq 1 ] && echo "$err" | grep -qi "no markdown"; then ok empty-directory; else bad "empty rc=$rc $err"; fi
echo "RESULT: $pass passed, $fail failed; scratch $base"; [ $fail -eq 0 ]
