# Contributing to Entropa

Status: contributions are NOT open yet. This repository is published so that anyone can read, run, fork and check it. The rules below describe how contributions will work once they are opened; until then issues and pull requests may be disabled or left unanswered.

## Before the release
Only the maintainer changes the code. Issues and pull requests are closed to outsiders (repository interaction limit). Forks are allowed under the licence.

## After the release
- Forks are always welcome (Apache-2.0).
- Pull requests are welcome. The maintainer is the only merger. Squash merges only.
- Every commit carries a DCO sign-off (`git commit -s`). You keep your copyright; your code is licensed to everyone under Apache-2.0.
- Required: CI green, gitleaks clean, the repo safety scan, tests written first (red, then green).
- Changes to cryptography, the verifier or the Egress Guard rules get an additional review.
- Good first contributions: documentation, tests, new attack cases for the OPEN test set, bug reports with a reproduction.
- The sealed test sets are private and are never shared with contributors. Accepted changes are run against them before merge; results are published, failures included.
- Security problems: do not open a public issue; follow SECURITY.md.

## Wording
Say "mapped to", "aligned with" or "tested against". Never "compliant", "certified" or "secure".

## No warranty
Provided as is, no warranty, use at your own risk (Apache-2.0 sections 7 and 8). The name "Entropa" is not licensed: forks must rename.
