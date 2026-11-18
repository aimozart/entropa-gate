#!/usr/bin/env bash
# S14b: red-first tests for scripts/governance-checks.sh (controls-map gaps T-A, T-B, T-E, T-F, T-G). Every case runs the
# script on a small fixture built in a temporary directory and checks the exit status AND the finding it names, so a check that
# can never fail (or never pass) is caught.
set -uo pipefail
cd "$(dirname "$0")/../.."
S=${GOV_SCRIPT:-scripts/governance-checks.sh}   # GOV_SCRIPT lets a broken copy be tested (the red-phase bite check)
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
# expect <name> <want-exit> <want-text-or-empty> <command...>
expect() {
  local name=$1 want=$2 text=$3; shift 3
  local out rc; out=$("$@" 2>&1); rc=$?
  if [ "$rc" -ne "$want" ]; then bad "$name (exit $rc, wanted $want): $out"; return; fi
  if [ -n "$text" ] && ! grep -qF -- "$text" <<<"$out"; then bad "$name (output lacks '$text'): $out"; return; fi
  ok "$name"
}
# T-B wording
printf 'This design is aligned with the shape of HITRUST e1.\nWe are never certified.\nMapped to the HIPAA rule; not assessed.\n' > "$T/good.md"
printf 'We are HIPAA compliant.\n' > "$T/bad1.md"
printf 'Fully certified by an auditor.\n' > "$T/bad2.md"
expect "wording: allowed phrasing passes" 0 "" "$S" wording "$T/good.md"
expect "wording: 'compliant' alone fails and names the line" 1 "bad1.md:1" "$S" wording "$T/bad1.md"
expect "wording: 'certified' alone fails" 1 "bad2.md:1" "$S" wording "$T/bad2.md"
expect "wording: one bad file among good ones fails" 1 "bad1.md:1" "$S" wording "$T/good.md" "$T/bad1.md"
printf 'Holds the AWS Certified Solutions Architect credential.\n' > "$T/cred.md"
printf '# credentials earned by a named person (exact phrases)\nAWS Certified\n' > "$T/allow.txt"
expect "wording: an earned credential name on the allow list passes" 0 "" env GOV_WORDING_ALLOW="$T/allow.txt" "$S" wording "$T/cred.md"
expect "wording: the same line without the allow list fails" 1 "cred.md:1" env GOV_WORDING_ALLOW="$T/none.txt" "$S" wording "$T/cred.md"
expect "wording: the allow list does not excuse another line" 1 "bad1.md:1" env GOV_WORDING_ALLOW="$T/allow.txt" "$S" wording "$T/bad1.md"
expect "wording: a missing file is an error, not a pass" 2 "" "$S" wording "$T/nope.md"
# T-E model SDKs
mkdir -p "$T/ws/crates/a" "$T/ws/crates/b" "$T/ws/crates/entropa-agent"
printf '[dependencies]\nserde = "1"\naws-sdk-kms = "1"\n' > "$T/ws/crates/a/Cargo.toml"
printf '[dependencies]\naws-sdk-bedrockruntime = "1"\n' > "$T/ws/crates/b/Cargo.toml"
printf '[dependencies]\naws-sdk-bedrockruntime = "1"\n' > "$T/ws/crates/entropa-agent/Cargo.toml"
expect "sdk: a model SDK outside the agent crate fails and names the crate" 1 "crates/b" "$S" sdk "$T/ws"
rm -f "$T/ws/crates/b/Cargo.toml"
expect "sdk: the KMS SDK and the agent crate are allowed" 0 "" "$S" sdk "$T/ws"
expect "sdk: a missing workspace is an error" 2 "" "$S" sdk "$T/none"
# T-F evidence index
mkdir -p "$T/ev/docs/evidence"; : > "$T/ev/docs/evidence/s1-red.txt"; : > "$T/ev/docs/evidence/s1-check.txt"
printf '| Stage | Branch | Head | Proved | Red | Green | Tests |\n|---|---|---|---|---|---|---|\n| S1 | `b` | abc | x | s1-red.txt | s1-check.txt | 1/0/0 |\n' > "$T/ev/docs/EVIDENCE-INDEX.md"
expect "evidence: every named file exists" 0 "" "$S" evidence "$T/ev"
printf '| S2 | `c` | def | y | s2-red.txt | s1-check.txt | 1/0/0 |\n' >> "$T/ev/docs/EVIDENCE-INDEX.md"
expect "evidence: a named file that is missing fails and is named" 1 "s2-red.txt" "$S" evidence "$T/ev"
# T-G test-change reasons
R="$T/repo"; git init -q "$R"; git -C "$R" config user.email t@example.invalid; git -C "$R" config user.name t
mkdir -p "$R/crates/x/tests"; printf 'a\n' > "$R/crates/x/tests/t.rs"; git -C "$R" add -A; git -C "$R" commit -q -m base
BASE=$(git -C "$R" rev-parse HEAD)
printf 'b\n' > "$R/crates/x/tests/new.rs"; git -C "$R" add -A; git -C "$R" commit -q -m "adds a new test file"
expect "testchange: adding a test file needs no reason" 0 "" "$S" testchange "$R" "$BASE..HEAD"
printf 'weakened\n' > "$R/crates/x/tests/t.rs"; git -C "$R" add -A; git -C "$R" commit -q -m "tweak an accepted test"
expect "testchange: changing an accepted test without a reason fails and names the commit" 1 "tweak an accepted test" "$S" testchange "$R" "$BASE..HEAD"
printf 'fixed\n' > "$R/crates/x/tests/t.rs"; git -C "$R" add -A; git -C "$R" commit -q -m "fix a helper" -m "Test change: the helper overwrote the field under test."
expect "testchange: a commit with a reason line passes" 0 "" "$S" testchange "$R" "HEAD~1..HEAD"
# T-A P0 question
printf -- '- 2026-10-20 S0: old line without the question.\n- 2026-10-22 S9: new line. P0: no real data, nothing leaks.\n' > "$T/do-good.md"
printf -- '- 2026-10-22 S9: new line with no data-safety answer.\n' > "$T/do-bad.md"
expect "p0: a dated line from the cutoff on that answers the P0 question passes (older lines are exempt)" 0 "" "$S" p0 "$T/do-good.md" 2026-10-21
expect "p0: a line from the cutoff on without the answer fails and names the line" 1 "do-bad.md:1" "$S" p0 "$T/do-bad.md" 2026-10-21
expect "p0: unknown check name is an error" 2 "" "$S" frobnicate
exit $fail
