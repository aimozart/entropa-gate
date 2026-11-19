# entropa-check: test your own guard with a set you cannot quietly adjust

`entropa-check` runs a fixed set of test cases against your guard once, and writes a report you can hand to someone else. A guard here is any program that reads text on standard input and prints `allow` or `block`.

**Status: in progress.** Build it from source for now: `cargo build --release -p entropa-check`. Nothing on this page downloads or installs anything, and the tool never uses the network.

## Why a "sealed" run
It is easy to fool yourself with your own tests: look at the failures, tweak the guard, re-run until it passes, then report the last run. `entropa-check` makes that hard to do by accident:
- **The set is pinned.** You give the SHA-256 of the set file; if the file differs by one byte the run is refused before anything is read.
- **You write down what you expect first.** The forecast says, per measure, the range you expect. The report then shows hit or miss for each, so a surprise stays visible.
- **One run per report.** A second run into the same report file is refused. A new run needs a new report, and the old one stays.
- **The report keeps the cases private.** It holds counts, 95% bounds, case ids, class names and hashes. It never holds a case input, anything your guard printed, or a secret.

## Ten-minute tour (with the sample that ships in `crates/check/sample`)
The sample is 40 synthetic cases and two guards. `guard-flawed.sh` has one planted flaw: it blocks the made-up key shape `SYNKEY-<16 hex digits>` only in upper case. `guard-fixed.sh` blocks it in any case.

```
cd crates/check/sample
SHA=$(sha256sum sample-set.json | cut -d' ' -f1)
entropa-check sealed --file sample-set.json --sha $SHA --out /tmp/flawed.json \
  --target ./guard-flawed.sh --forecast sample-forecast.json --no-prereg
```
Output:
```
report written: /tmp/flawed.json
cases: 40
failed: 8 of 40
accepted attacks: 8
upper95 of the failure rate: 0.321477
pre-registration: none given (unregistered run)
forecast: 0 hit, 3 miss
```
The eight lower-case keys got through. The forecast expected a clean guard, so all three of its expectations are marked as misses. Now the fixed guard, into a new report:
```
entropa-check sealed --file sample-set.json --sha $SHA --out /tmp/fixed.json \
  --target ./guard-fixed.sh --forecast sample-forecast.json --no-prereg
```
```
report written: /tmp/fixed.json
cases: 40
failed: 0 of 40
accepted attacks: 0
upper95 of the failure rate: 0.072158
pre-registration: none given (unregistered run)
forecast: 3 hit, 0 miss
```
Zero failures in 40 cases does not mean "never fails": the 95% upper bound is still 7.2% (the "rule of three": 3 divided by 40). More cases tighten it.

What the refusals look like (each exits with code 2 and does nothing else):
```
refused: a report already exists at that path; a sealed set is run once
refused: the sha256 of the file is not the given one; nothing was parsed
refused: no pre-registration: give one, or state --no-prereg (the report will say the run was unregistered)
```

## The stricter way: register before you run
1. Write your set (format `entropa-sealed-v1`) and your forecast (`entropa-forecast-v1`: for each measure, the range you expect, written before you run).
2. Make a signed pre-registration with a key that is not your release key:
   `entropa-check prereg make --stage my-stage --file set.json --forecast forecast.json --target ./my-guard --key prereg.seed --out prereg.json --not-key-id <your release key id>`
   (create the seed file with `entropa-release keygen --out prereg.seed`). Add `--anchor-ledger DIR` to also append a hash-only record to a local ledger made by `entropa-gate init`; the ledger's signed checkpoints then fix the order of events.
3. Run: `entropa-check sealed --file set.json --sha <sha256 of the set> --out report.json --target ./my-guard --forecast forecast.json --prereg prereg.json --prereg-pubkey <public key hex> [--anchor-ledger DIR]`.

The run is refused if the set, the forecast, the runner or your guard differ from what was signed. Without a pre-registration, the run is refused unless you pass `--no-prereg`, and then the report says it was unregistered.

## What the report holds
Counts, 95% bounds (rule of three when there are no failures, Wilson otherwise), case ids, class names, hashes, a closed list of failure reasons, and one row per forecast measure: your range, the measured value, hit or miss, bar met or missed. It never holds a case input, anything your guard printed, a secret from the set, or a file path.

## Honest limits
- A signature over hashes shows who committed to what. It shows when only if the record is anchored (a ledger you trust, or a timestamp service); unanchored, the date is whatever the file says.
- The guard hash covers the guard file only, not the programs it calls or the files it reads.
- The tool measures what your guard does on your cases. It cannot tell you the set is unbiased: a set written by someone who has already seen the guard will flatter it. Have someone else write the sealed set.
- `entropa-check mutate` and `entropa-check fuzz` only wrap `cargo-mutants` and `cargo-fuzz` if you already have them installed. They refuse to start with under 25 GB of free disk and cap memory at 6 GB when `systemd-run` exists.
- This is a measurement aid, not a certification: it does not make a guard safe, and it says nothing about cases you did not write.
