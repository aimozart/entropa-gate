# S7c: mutation results for entropa-ledger and the unkillable mutants

Capped container (24g, 12 CPUs, 4096 pids), jobs 2. Run 1: 420 mutants, 88 missed. Run 2 (after the golden timeline and boundary tests): 420 mutants, 375 caught,
26 unviable, 1 timeout (counted caught), 18 missed. Final focused re-run of bundle.rs and event.rs after the last tests: 182 mutants, 164 caught, 11 unviable, 7 missed.
Every remaining survivor (12 across the crate) is equivalent or cannot be reached with real input:
- `bundle.rs:240` (export) and `bundle.rs:495` (verify): `a.size == 0 || a.size == b.size` -> `&&`: for two checkpoints of equal non-zero size the core's own
  `consistency_proof` / `verify_consistency` already return an empty proof and require equal roots, so both paths give the same answer.
- `bundle.rs:289`: `text.len() > MAX_BUNDLE_BYTES` in the exporter: a bundle of exactly 5 MiB cannot be produced by a real store (the verifier's exact limit is tested with padding).
- `bundle.rs:447`: `pk.is_empty() || !verify_hex(...)` -> `&&`: `verify_hex` returns false for an empty key, so the result is the same.
- `event.rs:144`: `text.len() > MAX_EVENT_BYTES` in `encode_event`: the largest valid event is about 7.5 KB (the fields are all bounded), so the limit cannot be reached by encoding.
- `generator.rs:69`: the witness store's version counter `v + 1` -> `v * 1`: the generator is the only writer, so a stale-version conflict cannot occur.
- `generator.rs:412` and `generator.rs:485`: `ts + 1` and `last_ts + 10` -> `-`: each scenario starts at least 60 s after the previous one, so `start + 60 * (i + 1)` always dominates the `max(...)`; these terms never decide the timeline.
- `generator.rs:470`: `scenarios > MAX_SCENARIOS` -> `>=`: the exact boundary would mean generating 10,000 scenarios in a test (the `==` variant timed out, i.e. was caught).
