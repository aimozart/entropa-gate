# Known limits and gaps

A plain list of what is not done, not tested, or not decided. It is part of the results, not an appendix.

## Evidence quality
- Pinned data files whose metadata was edited for publication are listed in `crates/standards/PUBLISHED-NOTE.md` with a second, metadata-independent proof. The code-freeze records of earlier sealed rounds pin the source of their own round and are not shipped; data-freeze files, which tests check, are shipped.
- Some cited records are internal and are not published. They are marked `[evidence: stage record, not published]`; a claim that cites one cannot be re-checked from this repository, only from the measurements and tests that do ship (`docs/evidence/`, the test suites).

- Nothing here has had an independent review; the measurements are our own runs and one reviewer's re-runs of some of them. [evidence: docs/evidence/nodecore/]
- Test sets written by the same people who write the code measure what those people imagine; each new held-out round has found a family the previous rounds did not contain. [evidence: docs/results/results.json]
- The audit of crates for panics and unsafe code covers five crates; two others and the library crates under them are outside it. [evidence: docs/evidence/hardening/]
- Advisory and license checks of dependencies need tools that are not installed in this environment, so they were not run. [evidence: docs/evidence/s2/]

## Product gaps

- The egress guard is a heuristic scanner with known misses; it is not a complete secret filter. [evidence: docs/results/results.json]
- Retrieval over a sealed corpus does not yet resist all planted instructions. [evidence: docs/results/results.json]
- The gate's ledger record keeps coarse reasons: the precise denial word and the tier are hashed and dropped, so an explorer shows only two distinct sentences for 10,000 mock decisions. [evidence: docs/evidence/at2b/]
- Token usage meters live in the memory of one process and are lost on restart. [evidence: docs/evidence/at2b/]
- The core's append replays the whole ledger each time; opening a store is fast, appending is not yet. [evidence: docs/evidence/nodecore/]
- Refusing a duplicated JSON key in the node's request parser is a behaviour change that has not been deployed and needs its own review. [evidence: docs/evidence/nodecore/]

## Distribution gaps

- No release has been published: no signed program, no key, no fingerprint on two channels. [evidence: stage record, not published]
- The verify program is built for glibc-based Linux only; a static build was not made. [evidence: stage record, not published]
- The two reproducible builds ran on one host; reproducibility on another machine is not shown. [evidence: docs/evidence/s2/]
- The ledger copy for 10,000 records is 250 MB; a 1,000-record variant is 25 MB. [evidence: stage record, not published]
- The explorer pages were tested with a simulated page model, not in a real browser, and nothing is deployed. [evidence: docs/evidence/ls2/]
- Verification inside the browser does not exist; the native corpus it would be held to does. [evidence: docs/evidence/browser-corpus/]

## About this build

- The tamper-evidence rounds were measured on an earlier build of the verifier; this build differs in one file (the key order of the anchor file) and passes the same unit tests. [evidence: docs/evidence/ins2/FREEZE-3.md]
- Separate keys per ledger apply to the platinum nodes; the client app writes one ledger and uses one key file. [evidence: docs/evidence/ins2/FREEZE-3.md]

## Egress guard: what the sealed rounds measured

- **The egress guard in this build is the detector-based engine** that was measured in round 6 (1,539 cases): secrets leaked 468 of 1,042, personal identifiers 20 of 100, destinations 24 of 36 (the set's author judges the expectation of these a flaw of the set; they stay counted as failed), clean text wrongly blocked 21 of 340. It finds shapes it knows and misses others. [evidence: docs/results/results.json]
- **A different engine was measured in rounds 7 and 8 and is not part of this build:** a typed channel plus a word-list gate that accepts only text made of ordinary English words with plain punctuation. Round 7 (932 cases): free-text secrets leaked 0 of 216, clean prose refused 0 of 120, typed channel leaks 1 of 162 (the one case is a valid body the author wrote as a leak; real leaks 0 of 161). Round 8 (853 cases, after a digit budget and capitals and hyphen rules): secrets leaked 0 of 315, typed leaks 0 of 58, and a **price bar missed**: 80 of 290 realistic sentences refused, 27.6 percent against a bar of 25 percent. [evidence: docs/results/results.json]
- **What that engine cannot see, by design:** text written as ordinary words can carry information (passphrases 15 of 15 leaked in round 8), a code of up to eight digits in any shape passes (about 26.6 bits per message), digits spelled as words pass. It refuses person names and any text with non-ASCII letters. [evidence: docs/results/results.json]
- **Other rounds on the results page** (retrieval, the container attack round, the tamper-evidence rounds) list their failures next to their passes: retrieval abstention 123 of 150 against a bar of 146 and injection obeyed 15 of 150; the container round 442 of 448 scenarios, one genuine protocol gap (a request without a Host header answered 200). [evidence: docs/results/results.json]
