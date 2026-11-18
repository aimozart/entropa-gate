# Soak & Production-Readiness Report

Filled out from real evidence gathered 2026-08-18 through 2026-08-22, cross-checked against
the project notes § Pre-onboarding soak-test criteria (7 items) and the post-soak resilience
test plan (4 items). Status colors: 🟢 green (clean, evidenced) · 🟡 yellow (real gap or
incomplete, not a hard failure) · 🔴 red (blocking, unresolved failure).

## Soak-test criteria (the project notes's 7-point checklist)

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | 3 days untouched runtime, no chain/consensus code deploys | 🟢 | Anchor `00013-9kt` (2026-08-18T22:20:15Z) → window closed 2026-08-21T22:20:15Z, elapsed clean. Only deploy in-window (`00014-nnw`) was memory-only, correctly didn't reset per the project rules. |
| 2 | Height climbs monotonically, no resets/gaps | 🟢 | Height `97,306` (08-18) → `160,553` (08-22), continuous growth, zero gaps confirmed via full paginated fetch. |
| 3 | Zero `persistence: loaded chain failed verification` lines | 🟢 | None found in logs across the window. |
| 4 | Cloud Monitoring alerts stay quiet | 🟡 | **Not fully quiet.** Brain-failure alerts fired repeatedly (`08-19`, `08-20` incl. a new `429 RESOURCE_EXHAUSTED` mode), plus 3 memory-utilization alerts. Low severity, self-recovering, never touches customer tx — but a real deviation from "quiet," not glossed over. |
| 5 | *(reserved/no criterion 5 defined in source doc)* | — | — |
| 6 | At least one real deploy during the window, leader-lock proven | 🟢 | `00013-9kt` → `00014-nnw` transition: clean resume, zero `CHAIN_ROLLBACK`, clean leader-lease handoff (old lease correctly expired before new one acquired, zero overlap). |
| 7 | Full `Chain::verify()` against reconstructed live Firestore data | 🟢 | Re-run 2026-08-22 at height 160,543 → `VERIFY OK`, every hash link and ML-DSA signature checked. |

**Soak-test criteria: 6 of 6 defined items green, 1 yellow (alert quietness).**

## Post-soak resilience tests (4-item plan)

| # | Test | Status | Evidence |
|---|---|---|---|
| 1 | Attestation-proof corruption detection | 🟢 | Corrupted a real block's Firestore doc; live receipt endpoint never falsely confirmed (serves from memory, correctly unaffected); the actual detection surfaced on the resume attempt's `CHAIN_ROLLBACK` log — confirmed real. Repaired, re-verified `VERIFY OK`. |
| 2 | Mid-submission restart | 🟡 | **Not validly exercised.** The candidate instance failed before ever taking over serving traffic, so the real serving process never actually restarted — the intended race condition was never genuinely tested. |
| 3 | Deliberate rollback → new-epoch rotation | 🟢 | Real `CHAIN_ROLLBACK` observed, old epoch confirmed untouched (`current_epoch` pointer never flipped on the failed attempt — proves the design's all-or-nothing safety). Real O(n) cost bug found *because of* this test, then fixed (epoch-chaining) and redeployed clean. |
| 4 | Leader-lock re-confirmation under real redeploy | 🟡 | **Not validly exercised** for the same reason as #2 — no genuine overlap was produced by the failed candidate attempt. (Note: the *subsequent* `00013-9kt`→`00014-nnw` deploy *did* show a clean, real leader-lock handoff — but that was a planned memory-bump deploy, not a deliberate stress test of the failure mode this item targets. Worth deciding whether that counts as satisfying #4 or whether a dedicated test is still owed.) |

**Resilience tests: 2 of 4 genuinely green, 2 yellow (not validly exercised).**

## Additional production-health attributes (not in the original checklists, tracked because they matter)

| Attribute | Status | Evidence |
|---|---|---|
| Chain cryptographic integrity | 🟢 | `VERIFY OK`, 160,543 blocks, current as of 2026-08-22. |
| Memory headroom / O(n) growth | 🔴 | **The real blocker.** 3 stopgap bumps in 4 days (512Mi→1Gi→2Gi→4Gi), currently 65.99% of 4Gi. The actual fix (`Chain::bound_to_window`) is built, unit-tested, **still unwired**. Every prior ceiling got revisited within 1–3 days — this will recur without the real fix. |
| Public/private repo hygiene | 🟢 | `entropa-public` verified clean of all proprietary content; mirror-sync script in place; `gitleaks` 0 leaks both repos. |
| CI/security gates | 🟢 | Pre-commit runs full suite (fmt/clippy/test/secret-scan/audit); `entropa-public` CI green on every push. |
| Decision-outcome documentation | 🟡 | Real practice exists (`a project record (not published)`, 21 entries) but had a genuine drift (one entry's status went stale for 4 days before this review caught it) — now corrected, but proves the process needs periodic review, not just entries at write-time. |

## Overall verdict

**Not production-ready for real client onboarding.** Two genuinely green outcomes tonight — full
chain-integrity verification and the corruption/rollback resilience pair (tests 1 & 3) — are real
and strong evidence the core cryptographic/consensus design holds up under deliberate attack.

What keeps this at "not yet": **one red** (memory/O(n) growth — a known, recurring, unfixed failure
mode, not a hypothetical) and **three yellow** items (alert quietness, and resilience tests 2 & 4
never genuinely exercised). None of these are exotic edge cases — they're exactly the categories the
pre-onboarding checklist was built to catch.

## Path to production, in order

1. **Wire in `Chain::bound_to_window`** (main.rs/persistence.rs) — closes the one red item. Give it
   its own dedicated soak window per the standing one-change-at-a-time rule.
2. **Genuinely execute resilience tests 2 & 4** — needs a method that forces the actual serving
   instance to die (not a sibling candidate), now safer to attempt since the O(n) restart-cost bug
   that caused the last attempt to fail will be gone once step 1 ships.
3. **Re-run this report** after both — only then do all 11 tracked criteria (7 soak + 4 resilience)
   read green, which is the actual bar already set for handing over a real key.
