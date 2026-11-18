# Dev container limits and caches (S0h)

Everything runs in Docker through `in_dev` (scripts/lib-docker.sh). Since 2026-10-21 each container has hard
limits so a runaway (an unbounded allocation from a mutated test binary used 61 GiB on 2026-10-21; a fork bomb)
dies inside its cgroup and cannot take the PC down. Defaults suit this PC (62 GiB RAM, 20 cores) and are generous:
normal builds, tests and fuzz runs are not constrained; only a runaway is.

| Setting | Default | Override (environment) |
|---|---|---|
| Memory and swap | 24g / 24g (no extra swap) | `ENTROPA_DEV_MEMORY=32g` |
| CPUs | 12 | `ENTROPA_DEV_CPUS=8` |
| Processes | 4096 | `ENTROPA_DEV_PIDS=8192` |
| Address space per process (optional) | off | `ENTROPA_DEV_ULIMIT_V=<kB>` |
| Mutation jobs / per-mutant timeout | 4 / 30 s (S0i; was 2) | `ENTROPA_MUTANTS_JOBS=3` (or `JOBS=3`), `ENTROPA_MUTANTS_TIMEOUT=60` (or `MUTANTS_TIMEOUT=60`) |
| Light test mode for mutation runs only | `ENTROPA_FAST_TESTS=1` (set by `scripts/mutants.sh`) | `ENTROPA_FAST_TESTS=0` for full-strength tests |
| Fuzz RSS limit (libFuzzer) | 4096 MB | `FUZZ_RSS_MB=8192` |

`scripts/mutants.sh` and `scripts/fuzz.sh` print the limits they use. `ENTROPA_DEV_DRY_RUN=1` makes `in_dev`
print the docker command instead of running it.

`ENTROPA_DEV_ULIMIT_V` was measured on 2026-10-21: 12 GiB (12582912 kB) works for `cargo build` and `cargo test`,
but the AddressSanitizer fuzz run fails ("failed to allocate ... errno 12"), so it is off by default and must not
be used with `scripts/fuzz.sh`. The cgroup memory limit is the reliable one.

## Caches (all outside the repo, never committed, no secrets)
- `~/.cache/entropa-cargo` -> `/cargo/registry` and `~/.cache/entropa-dev/git` -> `/cargo/git`: downloaded crate
  sources only (mode 700 on `~/.cache/entropa-dev`). Nothing from the environment is written there.
- Build output stays in `./target` of the checkout (gitignored). To share one build cache between worktrees set
  `ENTROPA_TARGET_CACHE=$HOME/.cache/entropa-dev/target`; worktrees at different sources then rebuild what differs.

## Test
`scripts/tests/container-limits.sh` (also run by `scripts/check.sh`): the limit flags are on the docker command
line and overridable; then, only if they are present, an allocation bomb is run in a 512m container and must be
killed (exit 137) without host RAM dropping, and a fork bomb in a 64-process container must be stopped. The script
refuses to run the bombs if the flags are missing, so nothing ever runs uncapped. Red output before the change:
`docs/evidence/s0h-red.txt`.

## Rebuild by hand (no host installs are needed beyond Docker)
```
mkdir -p ~/.cache/entropa-cargo ~/.cache/entropa-dev/git && chmod 700 ~/.cache/entropa-dev
source scripts/lib-docker.sh   # builds the entropa-dev image on first use
in_dev cargo test --workspace --locked
```

## Faster mutation runs (S0i, 2026-10-21)
`scripts/mutants.sh` now defaults to 4 jobs and sets `ENTROPA_FAST_TESTS=1`. The variable is read **only in test helpers** (today `crates/ledger/tests/common/mod.rs`: at most 10 generator scenarios and 3 proptest cases; every assertion is unchanged), never in `src`, and `check.sh`, `count-tests.sh` and CI never set it (a script test, `scripts/tests/mutants-speed.sh`, checks the defaults through the dry-run output and that those gates stay clear of it). A survivor found in the light mode must be re-checked with `ENTROPA_FAST_TESTS=0` before it counts as a gap: the light mode can add survivors, not hide one.
Measured on the entropa-ledger crate (420 mutants, same machine, same container caps):
| Setting | Wall time | Missed |
|---|---|---|
| jobs 2, full tests (S7c run 2) | 37 min | 18 (before the last tests) |
| jobs 2, full tests (S7c run 1) | 47 min | 88 (before the tests that closed the gaps) |
| **jobs 4, light tests (S0i)** | **16 min (944 s)** | **12, the same documented equivalents as the full-strength run** |
Test suite alone (49 ledger tests, one process, no build): 26.7 s full, 12.5 s light. Peak container memory sampled every 5 s during the 4-job run: 6.9 GiB, well inside the 24 GiB cap (earlier note: about 10 GiB with 2 jobs on other crates, so check the peak when you raise the jobs or run a heavy crate; raise `ENTROPA_DEV_MEMORY` if it approaches the cap). The speed-up is 2.3x, not 4x: four compiles at once compete for the 12 CPUs, and the per-binary fixed costs (building the Cedar engine, generating keys) do not shrink in the light mode.
Other crates opt in by reading the same variable in their own test helpers.
