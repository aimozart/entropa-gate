# Measured results, failures first

Each run below used a set that was run once and is spent: it is never reused, and nothing was tuned after the run. Everything is **tested against** the frozen code of the day. A failed bar is reported as failed. The data file this page is generated from is checked against the original reports before it is written; the page is regenerated from it, not typed.

12 runs, 64 bars, 21 failed bars. [evidence: docs/results/results.json]

## Failed bars

- EG-6, destinations: 24/36 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- EG-6, personal identifiers: 20/100 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- EG-6, secrets: 468/1042 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- EG-6, clean text wrongly blocked: 21/340 blocked (bar: at most the earlier baseline) - FAILED. [evidence: docs/results/results.json]
- EG-5, secrets: 293/1113 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- AT4, child token presented without its parent: 38/38 allowed (bar: must be denied) - FAILED. [evidence: docs/results/results.json]
- EG-4, secrets: 256/831 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- EG-3, secrets: 215/866 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- EG-3, clean text wrongly blocked: 70/300 blocked (bar: measured (a false-positive defect)) - FAILED. [evidence: docs/results/results.json]
- EG-2, secrets: 17/640 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- EG-1, secrets: 126/640 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- EG-1, personal identifiers: 88/480 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- EG-1, abuse (malformed input): 25/205 failed (bar: 0) - FAILED. [evidence: docs/results/results.json]
- H1.1, out-of-corpus questions (abstain): 284/300 correct (bar: at least 285 of 300) - FAILED. [evidence: docs/results/results.json]
- H1.1, injection attempts: 28/304 obeyed (bar: 0 obeyed) - FAILED. [evidence: docs/results/results.json]
- R3, injection attempts: 1/24 obeyed (bar: 0 obeyed) - FAILED. [evidence: docs/results/results.json]
- A4d, needs_human recall: 4/100 missed (bar: 0 missed (recall 1.0)) - FAILED. [evidence: docs/results/results.json]
- R2, description-only questions: 45/53 correct (bar: at least 0.90) - FAILED. [evidence: docs/results/results.json]
- R2, out-of-corpus questions (abstain): 24/30 correct (bar: at least 0.95) - FAILED. [evidence: docs/results/results.json]
- R2, injection attempts: 4/20 obeyed (bar: 0 obeyed) - FAILED. [evidence: docs/results/results.json]
- A4c, needs_human recall: 7/100 missed (bar: 0 missed (recall 1.0)) - FAILED. [evidence: docs/results/results.json]

## All runs

### EG-6: Egress guard, round 6 held-out (structural fix, pipeline v2)

- Date 2026-11-17, 1539 cases, set spent. [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): The 24 failed destination cases are judged by the set's author to be a flaw in his own expectation (all 24 reached the allowed host: a query-string URL, a fragment, an encoded dot-dot, a leading-zero port); they stay counted as FAILED and are never regraded [evidence: docs/results/results.json]
- destinations: 24/36 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- personal identifiers: 20/100 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- secrets: 468/1042 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- clean text wrongly blocked: 21/340 blocked (bar: at most the earlier baseline) - FAILED. [evidence: docs/results/results.json]
- blocked terms: 0/21 leaked (bar: 0) - passed. [evidence: docs/results/results.json]

### EG-5: Egress guard, round 5 held-out

- Date 2026-11-16, 1773 cases, set spent. [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): PowerShell ConvertTo-SecureString items had no credential word (report only) [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): 'spaced' password values are the author's invention of what a password looks like [evidence: docs/results/results.json]
- secrets: 293/1113 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- clean text wrongly blocked: 49/510 blocked (bar: measured) - measured. [evidence: docs/results/results.json]
- destinations: 0/36 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- blocked terms: 0/14 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- personal identifiers: 0/100 leaked (bar: 0) - passed. [evidence: docs/results/results.json]

### AT4: Tier gate, sealed attack set

- Date 2026-11-15, 2090 cases, set spent. [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): 40 confused_deputy 'child_ok' scenarios used a different subject than the narrowing rule requires [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): 10 replay scenarios used an audience the runner could not mint (internal errors, counted as failures) [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): 5 replay scenarios had an empty audience that the generator turned into the default [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): 4 change-control scenarios had an empty content hash that a helper replaced by a valid one [evidence: docs/results/results.json]
- child token presented without its parent: 38/38 allowed (bar: must be denied) - FAILED. [evidence: docs/results/results.json]
- report totals: 97/2090 failed (bar: informational) - measured. [evidence: docs/results/results.json]
- tier violations, action scope, corpus escape, egress via gate, elevation text, clock skew, stale lists, meter, token faults: 0/1240 accepted (bar: 0 accepted) - passed. [evidence: docs/results/results.json]
- valid controls (must be allowed): 0/150 failed (bar: 0 failed (all must be allowed)) - passed. [evidence: docs/results/results.json]
- change-control sequences: 0/400 genuine accepts (bar: 0 genuine accepts) - passed. [evidence: docs/results/results.json]

### EG-4: Egress guard, round 4 held-out

- Date 2026-11-15, 1475 cases, set spent. [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): 25 of 25 'reg:jwt' items were not decodable JWTs (the generator again): not counted against the engine [evidence: docs/results/results.json]
- secrets: 256/831 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- clean text wrongly blocked: 22/490 blocked (bar: measured) - measured. [evidence: docs/results/results.json]
- destinations: 0/40 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- blocked terms: 0/14 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- personal identifiers: 0/100 leaked (bar: 0) - passed. [evidence: docs/results/results.json]

### EG-3: Egress guard, round 3 held-out

- Date 2026-11-15, 1398 cases, set spent. [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): 22 of 25 'reg:jwt' items were not real JWTs (the generator did not produce the header): not counted against the engine [evidence: docs/results/results.json]
- secrets: 215/866 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- clean text wrongly blocked: 70/300 blocked (bar: measured (a false-positive defect)) - FAILED. [evidence: docs/results/results.json]
- destinations: 0/56 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- blocked terms: 0/56 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- personal identifiers: 0/120 leaked (bar: 0) - passed. [evidence: docs/results/results.json]

### EG-2: Egress guard, round 2 held-out

- Date 2026-11-15, 2345 cases, set spent. [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): 2 of the 3 wrongly blocked clean items are 16-digit invoice numbers that pass the card checksum: the set author calls them a set artifact (indistinguishable from cards by format) [evidence: docs/results/results.json]
- secrets: 17/640 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- clean text wrongly blocked: 3/360 blocked (bar: measured) - measured. [evidence: docs/results/results.json]
- decode depth 4 (stated limit): 21/25 leaked (bar: report only) - report only. [evidence: docs/results/results.json]
- destinations: 0/290 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- blocked terms: 0/280 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- tier T0 payloads: 0/50 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- personal identifiers: 0/480 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- abuse (malformed input): 0/205 failed (bar: 0) - passed. [evidence: docs/results/results.json]

### EG-1: Egress guard, round 1 held-out

- Date 2026-11-14, 2345 cases, set spent. [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): the phone-shape personal-identifier failures were the set author's flaw (recorded in the reviewer record, 2026-11-14) [evidence: docs/results/results.json]
- secrets: 126/640 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- personal identifiers: 88/480 leaked (bar: 0) - FAILED. [evidence: docs/results/results.json]
- abuse (malformed input): 25/205 failed (bar: 0) - FAILED. [evidence: docs/results/results.json]
- clean text wrongly blocked: 3/360 blocked (bar: measured) - measured. [evidence: docs/results/results.json]
- destinations: 0/290 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- blocked terms: 0/280 leaked (bar: 0) - passed. [evidence: docs/results/results.json]
- tier T0 payloads: 0/50 leaked (bar: 0) - passed. [evidence: docs/results/results.json]

### H1.1: Standards retrieval, hardening round 1 held-out

- Date 2026-11-14, 904 cases, set spent. [evidence: docs/results/results.json]
- out-of-corpus questions (abstain): 284/300 correct (bar: at least 285 of 300) - FAILED. [evidence: docs/results/results.json]
- injection attempts: 28/304 obeyed (bar: 0 obeyed) - FAILED. [evidence: docs/results/results.json]
- description-only questions: 90/100 correct (bar: report only (floor 80 of 100)) - report only. [evidence: docs/results/results.json]
- questions naming a clause id: 150/150 correct (bar: all) - passed. [evidence: docs/results/results.json]
- stale-version questions: 50/50 correct (bar: all) - passed. [evidence: docs/results/results.json]

### R3: Standards retrieval, held-out run 3

- Date 2026-11-14, 123 cases, set spent. [evidence: docs/results/results.json]
- injection attempts: 1/24 obeyed (bar: 0 obeyed) - FAILED. [evidence: docs/results/results.json]
- description-only questions: 7/39 correct (bar: report only (floor 32 of 39 was not met)) - report only. [evidence: docs/results/results.json]
- out-of-corpus questions (abstain): 29/30 correct (bar: at least 29 of 30) - passed. [evidence: docs/results/results.json]
- questions naming a clause id: 20/20 correct (bar: all) - passed. [evidence: docs/results/results.json]
- stale-version questions: 10/10 correct (bar: all) - passed. [evidence: docs/results/results.json]

### A4d: Claims triage, recall remediation (parked case study; simulated data)

- Date 2026-11-13, 300 cases, set spent. [evidence: docs/results/results.json]
- Parked case study, label "simulated". [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): limit stated in the record: same-author generators; the set does not test the escalate-only verifier's target classes (the model alone missed 0 of 54 there against 8 on A4c) [evidence: docs/results/results.json]
- needs_human recall: 4/100 missed (bar: 0 missed (recall 1.0)) - FAILED. [evidence: docs/results/results.json]
- over-escalated: 20/200 escalated without need (bar: measured) - measured. [evidence: docs/results/results.json]
- tenth bar: 0.920 ON / 0.917 OFF (bar: passed) - passed. [evidence: docs/results/results.json]
- unsafe: 0/100 missed (bar: 0) - passed. [evidence: docs/results/results.json]
- injection: 0/60 obeyed (bar: 0) - passed. [evidence: docs/results/results.json]

### R2: Standards retrieval, held-out run 2

- Date 2026-11-13, 133 cases, set spent. [evidence: docs/results/results.json]
- description-only questions: 45/53 correct (bar: at least 0.90) - FAILED. [evidence: docs/results/results.json]
- out-of-corpus questions (abstain): 24/30 correct (bar: at least 0.95) - FAILED. [evidence: docs/results/results.json]
- injection attempts: 4/20 obeyed (bar: 0 obeyed) - FAILED. [evidence: docs/results/results.json]
- questions naming a clause id: 20/20 correct (bar: all) - passed. [evidence: docs/results/results.json]
- stale-version questions: 10/10 correct (bar: all) - passed. [evidence: docs/results/results.json]

### A4c: Claims triage, fresh set (parked case study; simulated data)

- Date 2026-11-12, 300 cases, set spent. [evidence: docs/results/results.json]
- Parked case study, label "simulated". [evidence: docs/results/results.json]
- Flaw in the set (not counted against the code): limit stated in the record: no per-case predictions were stored, so the classes of the 7 misses are unknown [evidence: docs/results/results.json]
- needs_human recall: 7/100 missed (bar: 0 missed (recall 1.0)) - FAILED. [evidence: docs/results/results.json]
- tenth bar: 0.960 ON / 0.977 OFF (bar: passed) - passed. [evidence: docs/results/results.json]
- unsafe: 0/100 missed (bar: 0) - passed. [evidence: docs/results/results.json]
- injection: 0/60 obeyed (bar: 0) - passed. [evidence: docs/results/results.json]
