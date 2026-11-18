#!/usr/bin/env python3
"""the project rules mechanical backstop.

L31 says every production function gets a test, written first. Nothing
mechanical enforced that until now -- it depended entirely on remembering to
do it, under pace, every single time, and that self-check failed more than
once (see the project history, 2026-08-27). This script is the structural half:
it fails a commit outright if it adds a new production function with zero
new test added anywhere in the same commit.

**What this can and cannot prove, stated plainly, per the project rules:**
- It CANNOT prove a test was written *before* the implementation -- git has
  no record of the order two staged changes were typed in. Only a human (or
  watching the actual tool-call sequence live, as the owner did the night
  this was built) can catch that specific violation.
- It CAN prove a commit isn't shipping a brand-new function with *zero*
  test coverage anywhere in that commit -- a real, mechanical floor that
  didn't exist before, closing the "walked straight past L31 and nobody
  but a human happened to notice" gap.
- It only inspects **staged** content (`git diff --cached`) -- it is a
  pre-commit gate, not a general-purpose lint. Running it with nothing
  staged is a silent no-op by design.
- Known false-positive shape: a pure rename (old fn removed, differently-
  named fn added, behavior and its test both unchanged) can look like "new
  untested function" if the commit doesn't also touch a `#[test]` line.
  This is a real, accepted limitation of a git-diff-only heuristic -- if it
  ever fires on a genuine rename, that's a judgment call to review, not a
  reason to disable the gate.
"""
import re
import subprocess
import sys

FN_RE = re.compile(
    r'^\s*(pub(\([^)]*\))?\s+)?(async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]'
)
TEST_ATTR_RE = re.compile(r'^\s*#\[test\]\s*$', re.M)


def run(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else ""


def staged_files() -> list[str]:
    out = run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"])
    return [f for f in out.splitlines() if f.endswith(".rs")]


def file_content(rev: str, path: str) -> str:
    # Git's "staged content" syntax is a bare leading colon with NO revision
    # name before it (`git show :path`) -- it is not "rev:path" with rev
    # substituted as ":", which produces an invalid "::path" double-colon ref.
    ref = f"{rev}:{path}" if rev else f":{path}"
    return run(["git", "show", ref])


def extract_top_level_fn_names(content: str) -> set[str]:
    """fn names defined outside any #[cfg(test)] module -- test helper
    functions and test cases themselves never count as "production code
    needing its own separate test"."""
    names: set[str] = set()
    depth = 0
    test_mod_depth: int | None = None
    pending_cfg_test = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#[cfg(test)]"):
            pending_cfg_test = True
        if test_mod_depth is None and pending_cfg_test and "mod " in stripped and "{" in stripped:
            test_mod_depth = depth
            pending_cfg_test = False
        in_test = test_mod_depth is not None and depth >= test_mod_depth
        if not in_test:
            m = FN_RE.match(line)
            if m:
                names.add(m.group(4))
        depth += line.count("{") - line.count("}")
        if test_mod_depth is not None and depth <= test_mod_depth:
            test_mod_depth = None
    return names


def has_new_test(old_content: str, new_content: str) -> bool:
    old_count = len(TEST_ATTR_RE.findall(old_content))
    new_count = len(TEST_ATTR_RE.findall(new_content))
    return new_count > old_count


def is_production_path(path: str) -> bool:
    return (
        path.startswith("crates/")
        and "/tests/" not in path
        and "/examples/" not in path
        and not path.endswith("_tests.rs")
    )


def main() -> int:
    files = staged_files()
    if not files:
        print("Test coverage gate: no staged .rs files, no-op.")
        return 0

    offenders: list[tuple[str, list[str]]] = []
    for f in files:
        if not is_production_path(f):
            continue
        old_content = file_content("HEAD", f)
        new_content = file_content("", f)
        old_fns = extract_top_level_fn_names(old_content)
        new_fns = extract_top_level_fn_names(new_content)
        added = sorted(new_fns - old_fns)
        # Checked per-file, deliberately -- a test added in an unrelated
        # staged file must never mask an untested function in this one. A
        # new function is covered only if *this same file's* test count grew,
        # matching this codebase's dominant co-located-test convention.
        if added and not has_new_test(old_content, new_content):
            offenders.append((f, added))

    if offenders:
        print("L31 coverage gate: new production function(s) added with ZERO new")
        print("test added anywhere in this commit:")
        for f, fns in offenders:
            print(f"  {f}: {', '.join(fns)}")
        print("")
        print("This does not prove a test was written first -- only a human watching")
        print("the actual tool sequence can catch that. It does prove this commit is")
        print("not shipping untested new logic. Write the failing test, confirm it")
        print("fails for the right reason, then implement, per the project rules.")
        print("If this is a genuine false positive (e.g. a pure rename), that's a")
        print("judgment call to review -- not a reason to skip this gate.")
        return 1

    print("Test coverage gate: no new untested production functions detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
