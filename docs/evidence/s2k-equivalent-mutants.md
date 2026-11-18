# S2k: equivalent (unkillable) mutants of entropa-hook, with the reason

Final whole-crate run (capped container: 24g memory, 12 CPUs, 4096 pids; cargo mutants --jobs 2 --timeout 30):
818 mutants, 713 caught, 46 timeouts (counted as caught: the mutant loops), 12 unviable, 47 missed.
The 47 misses were all equivalent or unreachable. Three were redundant code in bash.rs and paths.rs (removed,
behaviour unchanged, existing tests green); bash.rs and paths.rs were then re-measured: 366 mutants, 345 caught,
19 timeouts, 2 unviable, 0 missed. What remains is 44 mutants, all in shell.rs, listed below.

## Growth guards in shell.rs (38 mutants, lines 57, 115, 130, 233-235, 268, 288, 325)
S2k added guards so a mutant that stops an index advancing returns an error quickly instead of allocating
without bound (the runaway that used 61 GiB). On real input every token, word, substitution, delimiter and
heredoc body is made from input that was consumed, so none of them can outgrow the input; the guards never fire,
and a mutation of a guard's comparison or arithmetic cannot change any result. They are defence in depth.

## Equivalent by construction (6 mutants, shell.rs)
- shell.rs:101 `if *i < chars.len()` -> `<=`: at `*i == len` the increment only moves `*i` past the end, and the
  outer `while *i < chars.len()` ends in both cases; the body is identical.
- shell.rs:125 `start + 2` -> `start * 2` (the arithmetic `$((` test): no input distinguishes it; for start 0 and 1 it reads
  the same character, and the case `ab $((1+2))` was added and kills the `+ -> -` and other variants (one `*` variant survives).
- shell.rs:126 `i = start + 1` -> `start * 1`: starting at `$` instead of `(` only adds one `_ => i += 1` step.
- shell.rs:176 `'\n' if !pending.is_empty()` -> `true`: with nothing pending the arm does `i += 1` as the default arm.
- shell.rs:177 `i += 1` after a newline -> `-=` / `*=`: re-reads the previous line (or the newline) as a body line,
  which never equals a non-empty delimiter at that position and ends at the same index.

## Removed as redundant (behaviour unchanged)
- bash.rs `"env" if args.is_empty()` arm: unreachable, `resolve` never returns `env` as the program; a bare `env`
  is handled in the `let Some(..) else` branch (tests: `env`, `/usr/bin/env`).
- bash.rs `-d` / `-D` literal checks in the `git branch` guard: `has_short_flag(rest, 'd'/'D')` already covers them.
- bash.rs `a.len() > 1` in `has_short_flag`: `a[1..]` of `-` is empty and contains nothing.
- paths.rs `base == ".config/secrets" || ends_with("/.config/secrets") || ends_with("/.aws") || ends_with("/.ssh")`:
  each case is already caught by the `/.aws/`, `/.ssh/`, `/.config/secrets/` directory loop above it.

## S2l update (launchers: xargs, parallel, watch, find -exec; mv onto /dev/null)
bash.rs was re-measured under the same cap after S2l: 367 mutants, 345 caught, 20 timeouts (caught), 2 unviable,
0 missed. No new equivalent mutants. Three were removed by simplifying the code (the `watch` single-word guard) or
by tests of the depth limit through each recursing path (xargs, parallel, find -exec, watch). shell.rs is unchanged:
the same 44 documented equivalents above.

## S2m update (more launchers: setsid, ionice, taskset, chrt, flock, script, nsenter, unshare, chroot, systemd-run, su, runuser, at, batch)
bash.rs re-measured under the same cap: 414 mutants, 392 caught, 20 timeouts (caught), 2 unviable, 0 missed. No new
equivalent mutants. The first pass left 8 (long-form `--pid`, depth limit through the shell-string launchers, and the
`runuser -u` condition); each was killed by a test (tests/launchers_more.rs). shell.rs is unchanged: the same 44
documented equivalents above.

## S2n update (more launchers, inline interpreter code R6, awk and sed scripts)
bash.rs re-measured under the default container limits (24g, 12 CPUs, 4096 pids; jobs 2, timeout 30): 616 mutants, 570
caught, 39 timeouts (caught), 2 unviable, 3 missed. All three are equivalent:
- `pipeline_rules`: `if i > 0 && is_interpreter(prog)` with `>` -> `>=`: at i = 0 the producers slice `p[..0]` is empty, so nothing is read.
- `sed_risky`: `i += 1` in the default arm -> `*=`: the character is then re-read by the "inside a command" branch, which
  only reacts to `;`, newline and `}`, and the default arm is never entered on those, so the result is identical.
- `simple_rules_with`: `skip(k + 1)` -> `skip(k * 1)` in the `env -S` scan: starting at the `env` word itself only adds one
  comparison of `env` with `-S`, which is false.
Redundant code removed instead of documented: the `.contains("/.ssh/")` style fallback in `code_findings` (the
word-level `is_secret_path` check already covers directory components). shell.rs: the same 44 documented equivalents above.
