# Public documents

What this project is, what it defends against, what it does not, and how a reader can check the claims. Every statement in these documents has been **tested against** the code and data named in its evidence pointer, and says only what that evidence shows. Nothing here is a claim that the system is safe to rely on; the known limits are listed on their own page, and failures are reported next to successes.

How to read an evidence pointer: the bracketed label "evidence" followed by a path names a file in the repository (a source file, a plan with its measured outcome, a recorded run). A script (`scripts/check-public-docs.sh`) checks that every pointer is a tracked file; it cannot check that the file says what the sentence says, so the pointer is there for you to open.

All data here is synthetic. The signing keys used in the examples are throwaway keys made for mock ledgers.

| Page | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The parts and how they fit |
| [THREAT-MODEL.md](THREAT-MODEL.md) | What is defended (and how well), what is not |
| [VERIFYING.md](VERIFYING.md) | Steps a reader can follow to check a ledger |
| [RUN-IN-CONTAINER.md](RUN-IN-CONTAINER.md) | Running the checks in a clean container |
| [RESULTS.md](RESULTS.md) | Measured results of the held-out runs, failures first |
| [KNOWN-LIMITS.md](KNOWN-LIMITS.md) | What is not done, not tested or not decided |
| [GLOSSARY.md](GLOSSARY.md) | The words used |
