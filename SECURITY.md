# Security policy

This is a research prototype and has had no independent review. Please do not rely on it to protect real data.

## Reporting a vulnerability
Do not open a public issue for a security problem. Report it privately through the contact form at https://entropa.space/contact and say "security report" in the message. Include what you found, how to reproduce it and which commit you tested. There is no guaranteed response time; reports are read by one person.

## What is in scope
The code in this repository: the ledger and verifier, the egress guard, the token and tier gates, the retrieval service, the HTTP service and the scripts. Known weaknesses are listed in `docs/public/KNOWN-LIMITS.md` and in `docs/public/RESULTS.md`; a report that repeats a listed failure is welcome as a reproduction but is not a new finding.

## What is out of scope
Third-party services and platforms, and anything that needs access to private keys, which are never stored in this repository.
