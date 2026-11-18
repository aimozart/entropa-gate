# S12c: mutants that no test can tell apart (documented equivalents and timeouts)

Mutation runs: `scripts/mutants.sh entropa-council entropa-synthetic` (jobs 4, fast defaults; neither crate reads ENTROPA_FAST_TESTS, so no full-strength re-check is needed).
Run 1: 636 mutants, 46 missed, 2 timeouts. Run 2 (after tests for every survivor): 634 mutants, 2 missed, 2 timeouts. Run 3 (synthetic only, after one more test): see s12c-mutants-run3-synthetic.txt.

## Equivalent (1)
- `crates/council/src/planted.rs:248: delete ! in evaluate` (`flag = u64::from(!o.findings.is_empty())`). The hindsight gap is `|flag_bad - flag_good|` scaled by the number of pairs. Deleting the `!` complements EVERY flag, and `|(n - a) - (n - b)| = |a - b|`, so the reported gap is identical for every input. No test can distinguish it. Left as is on purpose: rewriting the expression to avoid the negation would not make the code clearer.

## Timeouts (2), counted as detected
- `crates/synthetic/src/lib.rs:180 and :190: replace + with * in scan`. The mutated scanner never advances (`from` stays put), so any test that calls `scan` hangs until the 90 s limit; a hang is a detection, not a survivor.

## Answered by a new test, not equivalent
- `ssn: 1 + derive % 9999` -> `1 * (derive % 9999)` still produced a reserved-invalid value (serial 0000 is also never issued) but broke the documented 0001-9999 range; a fixed sweep of 200,000 seeds now catches it (tests/mutation_gaps.rs g5).
- `independent()` had a redundant clause (`subject == Fake`), which produced an equivalent mutant; the clause was removed instead of excused.
