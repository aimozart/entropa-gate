# HITRUST Inheritance Posture — Entropa on GCP

**Status: built and documented, NOT certified.** Entropa has never undergone a HITRUST assessment and
makes no certification claim. This document analyzes what HITRUST-inheritable coverage Google's
platform assessment provides, and — more importantly — what it does *not*, so Entropa's own
responsibilities are explicit rather than assumed.

## Source

- **File:** `05172026 HITRUST SRM v1.5.5 Inheritance Provider Google.xlsx` (HITRUST Shared
  Responsibility Matrix, Baseline Template v1.5.5, CSF v9.1–v11.8)
- **Provider assessment:** 2025 GCP & Workspace, v11.6.0 r2, validated 2025-12-19
- **Machine-readable extract:** [`hitrust_gcp_inheritance.json`](hitrust_gcp_inheritance.json) — every
  BUID (control identifier) and its inheritability classification, parsed verbatim from the SRM.

## The numbers

Of **3,342** HITRUST CSF requirements in the matrix, Google's assessment allows:

| Inheritability | Count | % | Meaning |
|---|---:|---:|---|
| **Full inheritance** | 77 | 2.3% | Fully satisfied by Google's platform assessment — Entropa inherits these, no separate control needed |
| **Partial inheritance** | 415 | 12.4% | Google covers the infrastructure layer; **Entropa still owns an application-layer component** |
| **No inheritance** | 2,850 | 85.3% | Entirely Entropa's responsibility — Google's assessment doesn't reach these at all |

**The takeaway that matters:** running on GCP inherits roughly one-seventh of HITRUST's control
surface (full + partial combined, ~15%). **The other ~85% is squarely on us**, regardless of cloud
provider. This is normal — physical security, hypervisor isolation, and data-center controls inherit;
application security, access management, and data handling do not.

## Where full inheritance concentrates

Full-inheritance BUIDs cluster heavily in one domain (control family `18`, 52 of 77 — physical/data
center and infrastructure-facility controls), which is exactly what you'd expect: Google can prove
their data centers are physically secure; they cannot prove *Entropa's* application handles secrets
correctly. That's on us.

## Why Entropa's own surface is smaller than most

This is where the product's design decisions actually pay off in compliance terms, not just pitch
terms:

- **Data-minimal by construction.** Entropa never stores customer data — only a hash, a signature, and
  a timestamp (see `POSITIONING.md`). Whole categories of HITRUST requirements (data retention, PII
  handling, breach notification for *stored data*) become **not applicable** rather than "needs a
  control," because there's no data to lose.
- **No fungible token, no payment data in the ledger.** Removes another category (financial data
  handling) from the applicable surface entirely.
- **Deterministic, auditable write pipeline.** Every submission follows a fixed envelope — authenticate
  → rate-limit → queue → sequence → append to a signed Merkle log → checkpoint — with no discretionary
  or AI-driven step in the write path itself (the earlier AI-decision-making "Probe" design was retired
  in favor of this simpler single-writer transparency log; see `ARCHITECTURE.md`). That determinism is
  itself evidence toward access-control and audit-logging requirement families — not a control we'd
  have to bolt on separately.

None of this is a substitute for actually walking the ~85% and mapping each applicable requirement to
a real control. It does mean the *honest* starting surface is smaller than a typical SaaS handling raw
customer data.

## What "built, not certified" means in practice

- ✅ **Built:** this analysis, the machine-readable inheritance data, and the application-layer controls
  Entropa's own architecture already provides as defaults — least-privilege service-account IAM (see
  the project notes's per-service-account role grants), no customer PII in the data path by design,
  signing keys held only in Secret Manager and never logged (see `SECURITY.md`).
- ❌ **Not built:** an accredited HITRUST assessment. That requires an authorized external assessor
  and is a paid, multi-month engagement — out of scope until there's a paying customer who requires it.

## Next steps (not yet done)

1. Walk the 415 partial-inheritance BUIDs and identify which application-layer half of each Entropa
   must implement (e.g., GCP inherits network isolation; Entropa still owns its own IAM policy design).
2. Encode the controls Entropa *does* own as Pulumi (Go) assertions/tests — compliance-as-code, so
   "built, not certified" has a running test suite behind it, not just a document.
3. Revisit if/when a customer's procurement process requires an actual HITRUST assessment.
