# CONTROLS-MAP: policy statement -> mechanism -> evidence -> status -> proving test (stage S14a, design and mapping only)

Status: v1 DRAFT of the mapping, 2026-10-22. Branch `rerust-s14a-governance-arch`. Nothing here is a claim of compliance or certification: the wording is **"aligned with"** and **"mapped to"** only. Every statement of the 13 approved policies (P0-P12, internal approval 2026-10-21, **not published**; text in the reviewer's repository `docs/policies-draft/`) has one row. **Anything a policy requires that the code cannot yet show is a tracked gap, never a claim.**

## 1. How to read it
**Status vocabulary.** *implemented* = the mechanism exists AND a check anyone can re-run proves it in this repository. *partial* = part of the statement is implemented and the rest is a named gap. *planned* = designed or named in a policy but nothing proves it yet. *inherited* = provided by the cloud provider's platform (our configuration of it is a separate row). *n/a* = does not apply until a stated condition holds (for example "real PHI"). A **†** marks evidence that lives **outside this repository** (mostly the reviewer's repository: cloud inventories, RBAC scripts) and that **I, the author, did not verify**: I have not read any cloud configuration.
**Owner column:** *ours* (we configure or build it), *shared* (a provider's platform control plus our configuration), *process* (a human or team procedure, no code can prove it), *human* (the Human Principal's own action).
**Proving test shorthand:** `T:<crate>/<file>` = `cargo test -p entropa-<crate> --test <file>`; `T:<crate>` = every test of that crate; `S:<name>` = `scripts/<name>`; `C` = `scripts/check.sh` (fmt, clippy, all tests in both feature sets, doc, deny, audit, the public-readiness preflight, the container-limit and script tests). Everything runs through Docker (`source scripts/lib-docker.sh; in_dev ...`).
**What the author cannot show from code** is listed as `process`; for those rows the evidence is the dated record (stage reports, `docs/EVIDENCE-INDEX.md`, `a project record (not published)`).
**Wording rule for all public text and the résumé:** "aligned with" or "mapped to"; never "compliant" or "certified" unless earned; no PHI is processed (all data is synthetic); the BAA question is stated plainly (no real PHI means the Security Rule does not attach to the demo, but the design follows its safeguards; a signed BAA with each provider comes first if real PHI is ever on the table).
**Scope decisions still open (the owner's):** which **HITRUST** reference scope the alignment statement uses (an e1 / i1-style subset or the CSF categories): **I need his requirement list, I will not guess**; the HITRUST shared-responsibility inheritance workbooks are licensed ("shared as is in full"): **nothing from them is copied into this repository**, and inheritance in this map is stated only in our own words (default: ours; inherited only where the provider's inheritance is full; shared where partial, with the customer-side remainder written down).

## 2. Row 0 (first, by the owner's order): P0, patient and client data safety comes first
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P0.1 | Data safety comes first, always, even when mocked | the rule itself (a project record (not published), section "P0"); every stage report asks "could this leak or look like real data?" | implemented (process) | stage reports; `docs/EVIDENCE-INDEX.md` | process | the question is a manual checklist item; no automated check that a stage report answered it (proposal T-A below) |
| P0.2 | Healthcare and banking data is synthetic and labelled; no real data in any system, prompt, log, ledger event, repository, public page | closed-code event schemas (`crates/ledger`, `crates/council`), `synthetic: true` in the bundle, hook rule S2, canary refusal, repository scans | partial | `T:ledger/bundle` (b1, b5: `synthetic` must be true), `T:council/events` (e7 no free text, e8 no canary), `T:synthetic/repo_scan`, `T:hook/rules_matrix` (S2) | ours | runtime **log** scan and **public-page** scan are open (no front end, nothing deployed); only SSN shapes and canaries are scanned repository-wide, not MRN, phone or email shapes |
| P0.3 | Synthetic data generated on demand from a seed, stored as little as possible; identifiers from reserved invalid ranges | `crates/synthetic` (SSN area 000/666/900-999 with group 00, `SYN-` MRN, fake names with `-Syn`, phone 555-01XX, `example.invalid` email) | implemented | `T:synthetic/ids` (20,000-case property tests i2, i3), `T:synthetic/mutation_gaps` (full output-space coverage), `T:synthetic/repo_scan` (t3) | ours | none known; mutation: 0 survivors (`docs/evidence/s12c-mutants-run3-synthetic.txt`) |
| P0.4 | Canaries planted in mock PHI; automated checks prove they never appear in prompts, logs, ledger events, bundles, public pages, model inputs outside the gate | canary mint and scanner (`crates/synthetic`); decoder refuses canaries in any field; model rendering scanned; repository and explorer bundle scanned | partial | `T:synthetic/canary`, `T:synthetic/repo_scan` (t1, t2), `T:council/events` (e8), `T:council/render` (m3) | ours | **logs** and **public pages** not yet scanned; canary-bearing mock PHI records exist only in tests, there is no mock-PHI fixture pipeline for the clinic and bank scenarios yet |
| P0.5 | Synthetic PHI handled as real under P2 | see P2.1-P2.6 | partial | see P2 | ours | see P2 |
| P0.6 | Suspected real data stops the work and starts incident response | hook rule S2 stops a command carrying a valid-range SSN shape; the rest is the incident procedure (P6) | partial | `T:hook/rules_matrix` (S2 cases) | process | no automated trigger of an incident record; the procedure is not yet written down (P6.3) |
| P0.7 | Every stage review asks: could this leak or look like real data? | same as P0.1 | implemented (process) | stage reports | process | as P0.1 |

## 3. P1 Zero trust
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P1.1 | Verify explicitly: every action authenticated and authorized when it happens | Cedar gate + approvals gate (`crates/policy`, `crates/approvals`); the hook for the team's own tool use (`the agent guard (not published)`, enforcing since 2026-10-21) | partial | `T:policy`, `T:approvals`, `T:hook` | ours | the gates are libraries: no deployed agent calls them yet; for the cloud agents this becomes true with S11c and Gate G1 |
| P1.2 | Least privilege: own key per actor, minimum rights; no standing broad credentials; short-lived or narrowly scoped cloud access | actor directory with one key and one role per actor (`crates/approvals`), Cedar role rules; cloud IAM and roles per the reviewer's RBAC blueprint | partial | `T:approvals/flow`, `T:policy/bound` (the role comes from the directory, not the request) | shared | one long-lived AWS CLI key is still to be retired (P11.3); cloud IAM state `†` (reviewer: `docs/CLOUD-INVENTORY.md`, `docs/RBAC-BLUEPRINT.md`) not verified by me |
| P1.3 | Assume breach: every control fails closed; logs tamper-evident; guardrails assume an agent can be wrong | Cedar default deny and errors deny; hook fails closed on bad input; checkpoints signed and witnessed; hash-chained hook audit | implemented | `T:policy/engine`, `T:policy/combine`, `T:hook/observe_and_failure`, `T:core`, `T:witness`, `T:hook/audit_order`, `S:verify-hook-audit.sh` | ours | witness not deployed (P4.2) |
| P1.3b | (same item) the Claude Code hook, Cedar and rate limits assume manipulation | hook rules G, D, B, S, R, P (the design of the agent guard (not published) section 4), explorer limiter | implemented | `T:hook` (all files), `T:explorer/limiter` | ours | the hook's pending S2p fix (two false positives) awaits acceptance |
| P1.4 | Prove it: claims come with evidence a stranger can re-run; "trust us" statements are not published | evidence files per stage (`docs/evidence/`), `docs/EVIDENCE-INDEX.md`, one command `scripts/check.sh` | implemented (process) | `C`; `docs/EVIDENCE-INDEX.md` | process | no automated check on public copy (proposal T-B: forbidden-wording scan) |
| P1.5 | Transparency by default: decisions, approvals, denials, policy changes recorded as data-minimal signed events, publicly verifiable for the demo | ledger events, bundle, explorer read API, in-browser verifier (design) | partial | `T:ledger`, `T:explorer`, `T:council/events` | ours | the public explorer and the WASM verifier are not built or deployed (Gate G1) |
| P1.6 | Separation of duties: nobody approves their own work; hard-rule actions need the Human Principal's own word | approvals gate (no self-approval; attestation never opens hard-rule classes), Cedar forbid, council session rules | partial | `T:approvals/flow` (r5), `T:approvals/boundaries`, `T:policy/combine`, `T:council/session` (s10) | ours | **the Human Principal has no signing key of his own yet** (council D3, +$1/month, "not now"): until then a hard-rule decision can only be attested, and attestation is refused for those classes, so these actions stay blocked by design; the control is sound, the positive path is not yet usable |

## 4. P2 Mock-PHI handling SOP
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P2.1 | Synthetic records labelled synthetic in the data and on every page | `synthetic: true` in events and bundle; the bundle verifier refuses `false`; public pages not built | partial | `T:ledger/bundle` (b1, b5) | ours | pages (explorer front end S7f+) |
| P2.2 | Synthetic PHI-shaped data classified PHI-equivalent: access only through the gate, encrypted in transit and at rest, never in logs, prompts or ledger events beyond closed codes and hashes | gate (Cedar/approvals); closed-code schemas; hash-only hook audit; encryption by cloud defaults | partial | `T:ledger/events`, `T:council/events` (e7), `T:council/render` | shared | encryption settings of the (not yet created) stores and the transport are cloud configuration, to be evidenced at deployment (CBOM, G1 item 9); no PHI-equivalent store exists yet |
| P2.3 | Agents see only what the task needs; the ledger holds only type, actor handle, subject hash, outcome, reference | strict decoders and closed lists; the deterministic context packer (design S13a) | partial | `T:ledger/events`, `T:council/events` (e5, e6, e7) | ours | the context packer is designed, not built (S13b, S13c) |
| P2.4 | Identifier-shaped fixtures generated at run time | SSN negatives built from parts (S12c P0 hygiene); hook S2; repository scan t3 | implemented | `T:synthetic/repo_scan` (t3, t4), `T:hook/rules_matrix` | ours | the S2 rule currently also denies reserved-invalid values (S2p fix pending) |
| P2.5 | Every access to PHI-equivalent data is an audited, authorized event; denied or anomalous access appears in the weekly council packet | `policy.decision` records and approval events (`crates/policy`, `crates/ledger`); council packet (core) | partial | `T:policy/record`, `T:ledger/generator`, `T:council/session` | ours | the council scheduler is not deployed; anomaly rules (override spike etc.) are designed, not coded; no PHI-equivalent store yet |
| P2.6 | Synthetic datasets have a stated retention and an approved disposal step; no deletion without the Human Principal's word and a separate yes/no | hook D1 (deletes) and D2 (cloud deletes); approvals class `delete` | partial | `T:hook/bash_mapping`, `T:hook/rules_matrix` (D1, D2), `T:approvals/flow` | process | the retention statement per dataset is not written (P9.3); a breach of the deletion rule by the author was found and recorded (docs/evidence/hook-window3-triage.md, LESSONS.md) |

## 5. P3 Access control and separation of duties
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P3.1 | Every agent and service has its own identity (handle and key) and one role; no shared identities | `Directory` (key id -> one role) in `crates/approvals`; role-based public handles and per-handle keys in `crates/ledger` | partial | `T:approvals/flow`, `T:ledger/events`, `T:ledger/generator` | ours | cloud-side per-role IAM `†` not verified; the cloud agents' identities do not exist yet |
| P3.2 | No actor approves, reviews or merges its own work; one key is never requester and approver of one action | approvals gate (no self-approval, including attestation on behalf of the requester) | implemented | `T:approvals/flow` (r5), `T:approvals/boundaries` (an attestation on behalf of the requester is self-approval) | ours | merging and review are process controls for the team (P8.2); no technical block on the author merging besides hook rule G4 (ask) |
| P3.3 | Conflicting roles are not held by one actor (matrix) | one role per key by construction (`Directory`); council `required_role` table | partial | `T:council/events` (e9), `T:approvals/flow`, `T:approvals/one_role` (S14b) | ours | `Directory::try_add` now refuses a second identity for a key (tested); the P3 matrix as written is still not a test per row, and callers still use the overwriting `add` (to be switched in a later stage) |
| P3.4 | Hard-rule actions need the Human Principal's own decision; an agent's attestation never opens them | `AttestationPolicy` (accepted only for `direction`), Cedar `hard-rule-actions-need-a-human`, council `AttestationNotAccepted` | implemented | `T:approvals/boundaries`, `T:policy/combine`, `T:council/session` (s10) | ours | as P1.6: the Human Principal's own key does not exist yet |
| P3.5 | Role changes and key issuance or revocation recorded as signed ledger events | `directory.actor` events; revocation rule "a key revoked at index N cannot sign after N" in the approvals replay | partial | `T:ledger/events`, `T:approvals/flow` | ours | no `actor.revoke` / rotation event type in the ledger yet; issuance is recorded only for the generator's demo directory |
| P3.6 | The honest limit is stated publicly: all actors are operated by one human | `docs/ARCHITECTURE-APPROVALS.md` (attestation), explorer identity pages design (section 8) | planned | n/a | process | the public transparency statement (S14a deliverable) is not written |
| P3.M1 | builder-agent MUST NOT approve or merge its own work, publish, spend, change permissions, delete without the word | hook (G, D, B, P rules) for the team; Cedar role `ai` rules for cloud agents | implemented | `T:hook`, `T:policy/engine` | ours | enforcing since 2026-10-21; its own false positives are being fixed (S2p) |
| P3.M2 | orchestrator-agent MUST NOT write production code, approve its own orders, publish, spend | convention of the team; Cedar role rules for cloud agents | partial | `T:policy/engine` (cloud side) | process | nothing technical stops the orchestrator session from writing code; the reviewer's session permissions `†` are not in this repository |
| P3.M3 | critic / contestor MUST NOT change production or approve | the session state machine only accepts their event types; they hold no credentials | implemented | `T:council/session` (s3 wrong roles, s1), `T:council/events` (e9) | ours | model adapters not built; the "no credentials" half depends on the deployment |
| P3.M4 | operator-agent MUST NOT approve spend or publishing, or change policy | role not created yet | n/a | none | ours | create the role with its Cedar rules when it exists |
| P3.M5 | log-signer, witness, generator sign or produce within their narrow function and MUST NOT read other actors' secrets | `CheckpointSigner` trait, witness pure core, generator keys from seeds (demo) | partial | `T:witness`, `T:kms`, `T:ledger/generator` | shared | KMS signer role in AWS `†`; witness not deployed |
| P3.M6 | human-principal is the only holder of final authority; approves policy, issues and revokes keys | Cedar role `human`; approvals hard-rule classes | partial | `T:policy/combine` | human | key issuance and policy approval as signed events need his key (above) |

## 6. P4 Audit logging and integrity
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P4.1 | Every AI decision, approval, policy change and operational event is a data-minimal signed ledger event | approval events, `policy.decision` records, `agent.invocation` (generator, provider `fake`), council events | partial | `T:ledger/events`, `T:policy/record`, `T:approvals/flow`, `T:council/events` | ours | the agent crate (S11c) that writes real `agent.invocation` events is not built; operational events beyond these kinds are not defined |
| P4.2 | Ledger append-only, checkpointed with ML-DSA-65; a witness countersigns | transparency log (`crates/core`), KMS ML-DSA key (live test S1), witness pure core (`crates/witness`), bundle verifier | partial | `T:core`, `T:kms` (captured KMS vector), `T:witness`, `T:ledger/bundle` | shared | witness not deployed (Azure, G1); public ledger not deployed |
| P4.3 | Each agent's tool-use audit is hash-chained, verified before trusted; only its chain-head hash is anchored in the ledger | `the agent guard (not published)` sealed chain, `S:verify-hook-audit.sh` | partial | `T:hook/audit_order`, `S:verify-hook-audit.sh` | ours | **anchoring the chain-head in the ledger is not implemented** (proposal T-D) |
| P4.4 | Cloud audit logs on and kept (CloudTrail multi-region with validation; GCP Admin Activity and Data Access for IAM, KMS, Secret Manager, Vertex AI) | cloud configuration, applied 2026-10-21 according to the policy | implemented † | reviewer: `docs/aws-rbac/03-verify.sh`, `docs/CLOUD-INVENTORY.md` | shared | **not verified by me**; Azure pending; retention period not stated |
| P4.5 | Logs contain no secrets, canary tokens or PHI-equivalent values; the canary scan passes before any log or evidence is published | gitleaks preflight, canary repository scan, hook audit stores hashes only | partial | `S:public-preflight.sh`, `T:synthetic/repo_scan`, `T:hook/audit_order` | ours | runtime log scan and the publication gate (masking, canary, secret scan, the owner's approval) are planned (S14a/S9) |
| P4.6 | Log review at least weekly and after every incident; a failed chain verification opens an incident | weekly council cycle (core implemented); `S:verify-hook-audit.sh` exits non-zero on a bad chain | partial | `T:council/session`; `S:verify-hook-audit.sh` | process | no scheduler deployed; no automatic incident record from a failed verification |
| P4.7 | The honest limit is stated: the ledger proves recorded events were not altered, not that nothing was omitted | stated in `docs/ARCHITECTURE-EXPLORER.md` section 14 and the stage reports | implemented (documentation) | docs | process | to repeat in the public transparency statement |

## 7. P5 AI use and human oversight
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P5.1 | Models only in the three approved places; everything else deterministic; one family per cloud (Gemini Flash, Nova; Azure none); Titan only for the optional memory index | static rules recorded (a project record (not published)); the pure crates carry no model or cloud dependency | partial | `T:council/static_checks` (g2), `T:explorer/static_checks`, `T:synthetic/static_checks` | ours | the agent crate with exactly three implementations does not exist yet (S11c); no repository-wide guard that no other crate depends on a model SDK (proposal T-E) |
| P5.2 | A model receives no PHI-equivalent data, secrets or canaries; inputs come from the deterministic context packer whose hash is recorded in the decision event | `render_for_model` (closed alphabet, canary refusal); the packer (design S13a, tests S13b) | partial | `T:council/render` (m1-m4) | ours | the packer and the `context_hash` field are not built |
| P5.3 | Model output is untrusted data: closed codes, schema validation, no tool authority beyond Cedar and approvals; precedents are evidence | strict decoders (council); Cedar/approvals decide; retrieval rules in the memory design | partial | `T:council/events`, `T:policy`, `T:council/session` | ours | the output parser for the real agents is not built (S11c/S13) |
| P5.4 | A human decision is required for hard-rule actions; attestation never satisfies them | as P3.4 | implemented | `T:approvals/boundaries`, `T:council/session` (s10) | ours | the Human Principal's own key (above) |
| P5.5 | Every agent has a model card, an AI impact assessment and a stated limit before it runs; a transparency statement says what is automated and what a human decides | S14a deliverables | planned | none | process | nothing written; no agent runs yet |
| P5.6 | Model reviewers pass planted-fault tests before adoption and after any change; a failing model is not adopted | `entropa-council` planted-fault harness; `evaluation.recorded` event | partial | `T:council/planted` (p1-p8), `T:council/events` | ours | not yet run against real models (no model adapters); thresholds are proposals until the owner accepts D4 of the council design (accepted by the reviewer) |
| P5.7 | A kill switch (signed halt) and circuit breakers exist and are tested before any agent runs in the cloud | AWS cost levels (pause at the hard cap) designed in docs/ARCHITECTURE-AWS-SHOWCASE.md section 8.2 | planned | none | ours | G1 item 5: signed halt event, breakers and their tests are not implemented |
| P5.8 | The council proposes and never changes production by itself; no quorum, no change | session state machine: `approved_changes` is empty without quorum and without a recorded human decision | implemented | `T:council/session` (s11, s12, s13), `T:council/carryover` | ours | the council is not deployed (a library) |

## 8. P6 Incident response and breach notification
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P6.1 | An incident is any suspected leak, credential exposure, failed audit chain, unexplained hook deny, unauthorized change, role breach; anyone stops and reports at once | the hook's denies and asks are the signal; stage reports and `a project record (not published)` record incidents (for example the deleted scratch files, 2026-10-21) | partial | `S:verify-hook-audit.sh`; `docs/evidence/hook-window3-triage.md` | process | reporting is by habit, not by a tool; the triage found three of my own breaches reported late |
| P6.2 | Suspected real data triggers P2 at once: stop, contain, tell the Human Principal | hook S2 deny; procedure | partial | `T:hook/rules_matrix` (S2) | process | procedure not written (P6.3) |
| P6.3 | Severity classes (S1 exposure, S2 integrity or policy failure, S3 near miss) and first responses are written down | an incident runbook | planned | none | process | `docs/runbooks/incident.md` does not exist (proposal in S14a deliverable 4) |
| P6.4 | Every incident is a signed ledger event and a written report (timeline, cause, impact, fix, preventing test or rule) | written reports exist for team incidents (LESSONS.md, evidence files); the `incident.recorded` event schema is not defined | partial | `docs/evidence/hook-window3-triage.md` | process | event schema and signing path planned (G1 item 8) |
| P6.5 | Containment actions that delete, spend, publish or change credentials follow the hard rules | hook D1, D2, B1, B2, S1; approvals classes | implemented | `T:hook/rules_matrix`, `T:approvals/flow` | ours | team side only; the cloud side is IAM at deployment |
| P6.6 | If real PHI were ever involved, HIPAA breach-notification duties are followed with counsel; no real PHI until a signed BAA exists | none needed while all data is synthetic | n/a | none | human | applies only if real PHI is ever on the table (decision D10 of the explorer design: separate review) |
| P6.7 | At least one incident drill is run and reported before Gate G1 passes, then quarterly | scenario list from the AI Incident Database and MIT repository themes (S14a deliverable 4), then a drill | planned | none | process | G1 item 8: no drill run yet |

## 9. P7 Risk analysis and review cadence
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P7.1 | A risk register exists (asset, threat, likelihood, impact, control, owner, status) covering each agent, cloud account, repository, public surface | `docs/RISK-REGISTER.md` | planned | none | process | not written |
| P7.2 | Threat models exist for the ledger, the explorer, the hook and each agent, updated when the design changes | `docs/THREAT-MODEL.md` (STRIDE, build and supply chain section written in S0b); design-level threat tables in the architecture documents | partial | docs | process | THREAT-MODEL.md covers the build and supply chain only; the per-component models live in the ARCHITECTURE-*.md threat tables and must be consolidated and kept current |
| P7.3 | Risks reviewed at the weekly council, triggered sessions and the monthly retrospective; an item without a decision stays pending | council cadence and state machine | partial | `T:council/session` (s12, s13) | ours | scheduler and retrospective not deployed |
| P7.4 | Access reviews (roles, keys, MFA) monthly and recorded | RBAC task sheet `†` | planned | none | human | no dated review record yet |
| P7.5 | Policies reviewed at least quarterly and after every incident; changes go through P8 | `policy.published` event (planned) with review dates | planned | none | process | next review date for v1 should be set (2027-01-21) |
| P7.6 | Residual risk accepted by the Human Principal is written down with reason and review date | `a project record (not published)` holds decisions; the register field is planned | partial | docs | human | no review dates on past acceptances |

## 10. P8 Change management
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P8.1 | Test first (red then green), red shown failing for the stated reason; stub tests checked against a deliberately broken implementation | red evidence per stage (`docs/evidence/*-red.txt`), the red-phase checklist (docs/STANDARDS.md), bite evidence (e5, replay) | implemented (process, evidenced) | `docs/EVIDENCE-INDEX.md` rows; `docs/evidence/s12c-e5-bite.txt` | process | no tool checks that each stage has its red evidence (proposal T-F) |
| P8.2 | Every stage reviewed independently by a different role on a fresh checkout; the author does not accept its own work | the reviewer reviews on fresh worktrees and records PASS | implemented (process) | the reviewer's acceptance messages; fresh-worktree `check.sh` runs | process | no technical enforcement (branch protection on a hosted remote would add it, P8.4) |
| P8.3 | Changes to accepted tests are separate commits with the reason; assertions are not removed or weakened without approval | commit discipline (S12c) | implemented (process) | `git log` of the S12c line | process | not enforced by tooling (proposal T-G: a commit-message check on files under accepted `tests/`) |
| P8.4 | Protected branches: PR with passing checks; no force pushes or branch deletions on protected branches; actions pinned by hash | hook G1 blocks force pushes by the AI; rulesets "staged" per the policy | planned | `T:hook/bash_mapping` (G1) | process | no hosted remote with rulesets yet (Gitea private); workflows under `.github/` are legacy and unpinned-actions status unchecked |
| P8.5 | Deployment waits for Gate G1 and the Human Principal's word; every deployment has a runbook, rollback, recorded decision | Gate G1 table (a project record (not published)); hook B2; approvals class `deploy` | implemented (process) | G1 table; `T:hook/rules_matrix` (B2) | process | runbooks planned |
| P8.6 | Dependency, container and workflow changes pass scanning (gitleaks, cargo deny/audit, SBOM) and introduce no unpinned inputs | `C` runs deny, audit, the preflight; `scripts/sbom.sh`; pinned gitleaks image digest, `rust-toolchain.toml`, `Cargo.lock` | partial | `C`, `S:sbom.sh` | ours | no automated check for unpinned inputs; SBOM is not part of `C` |
| P8.7 | Emergency changes are recorded afterwards with the same evidence | convention | implemented (process) | docs | process | none known |

## 11. P9 Data minimization, retention and disposal
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P9.1 | Collect and keep the minimum; ledger events carry codes, hashes and references only | strict closed-code decoders; hook audit hashes only | implemented | `T:ledger/events`, `T:council/events` (e5-e8), `T:ledger/boundaries` | ours | none known |
| P9.2 | Mock PHI synthetic, on demand from a seed, little stored, labelled; identifiers from reserved ranges | as P0.3 | implemented | `T:synthetic/ids` | ours | none known |
| P9.3 | Retention: audit evidence and policy documents at least six years once live; synthetic working data discarded after use; the ledger is append-only | explorer decision D9 (keep forever, yearly snapshot note) | planned | none | process | a retention table per store is to be written at deployment |
| P9.4 | Encryption at rest (AES-256, managed or customer keys) and TLS in transit; hybrid post-quantum key exchange where supported | cloud defaults; ML-DSA for signatures | planned | none | shared | the crypto inventory (CBOM) is G1 item 9 and not written; provider support must be read from official documentation |
| P9.5 | Backups encrypted; restore tested before Gate G1 and then quarterly | state backups to Gitea and a laptop (reviewer `†`); versioned buckets and a rebuild-from-ledger test (design S13) | planned | none | ours | **no restore test has been run** |
| P9.6 | Disposal follows the hard rule and is recorded | hook D1, D2; approvals `delete` | partial | `T:hook/rules_matrix`, `T:approvals/flow` | process | no disposal record schema |
| P9.7 | Logs and evidence for publication are masked (account IDs, ARNs with numbers, device lists) and scanned before release | `S:public-preflight.sh` scans; masking step and publication gate planned | planned | `S:public-preflight.sh` (scan half only) | ours | the masking tool and the owner's per-publication approval gate are not built |

## 12. P10 Third-party and cloud provider management
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P10.1 | Shared responsibility stated plainly; compliance never claimed as inherited as a whole | this map's Owner column and wording rule; designs' service-eligibility sections | implemented (documentation) | docs | shared | no scan of public copy for forbidden wording (proposal T-B) |
| P10.2 | Only eligible or covered services for PHI-equivalent data; each checked before use and quarterly | reviewer's HIPAA check `†` (2026-10-21); the standing rule and the per-design eligibility sections (a project record (not published); explorer 16, showcase 14, council 19, memory 10, harness 12) | partial | docs | shared | quarterly re-check not scheduled (next 2027-01-21); Titan, S3 Vectors, Bedrock features, Vertex AI carry "confirm" notes |
| P10.3 | A signed BAA with each provider exists before any real PHI | rule recorded (a project record (not published), standing rule 8) | n/a | none | human | applies only if real PHI is ever on the table |
| P10.4 | Inherited controls documented from provider attestation; our configuration evidenced separately | this map (Owner column); the reviewer's private HITRUST notes `†` | partial | docs | shared | HITRUST reference scope is the owner's choice (open); nothing from the licensed workbooks is reproduced here |
| P10.5 | Each provider account: spend limit or budget alert, strong MFA, recorded owner, no standing broad keys | AWS budget alerts and cost levels; the owner's accounts | partial † | reviewer inventory `†` | shared | GCP and Azure budgets to confirm; one long-lived AWS key to retire; Azure inventory pending |
| P10.6 | Provider and model changes reviewed before adoption; the planted-case suite re-run for models | planted harness (core); memory-index suite (tests S12d-b) | partial | `T:council/planted` | ours | not run on real models yet |
| P10.7 | Free-credit accounts never upgraded; credit expiry tracked, teardown planned | the global billing rules; `docs/FINOPS-LEDGER.md`; hook B1 (plan upgrade, billing) | implemented (process) | `T:hook/rules_matrix` (B1) | process | expiry dates are tracked by hand; no reminder automation |

## 13. P11 Secrets and key management
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P11.1 | Secrets never committed, pasted into chat, logged or put in prompts; agents do not read credential files | gitleaks (preflight in `C`, `S:secret-scan.sh`), `.gitignore` baseline, hook S1 (secret paths), permission rules | partial | `S:public-preflight.sh`, `T:hook/rules_matrix` (S1), `S:tests/gitignore-baseline.sh` | ours | pasting a secret into a chat is human behaviour: no technical control; other repositories (clinic-ops) are not covered by this repository's scan |
| P11.2 | Every human account uses strong MFA; recovery codes encrypted offline; super-admin self-recovery off where possible | the owner's accounts, applied per the policy | implemented † | reviewer inventory `†` | human | **not verified by me**; MFA is strong but not phishing-resistant (stated limit); the MFA checklist with one attestation line per account is G1 item 10 |
| P11.3 | Long-lived keys should not exist; agents and pipelines use short-lived credentials; remaining ones listed with owner and retirement date | AWS roles with MFA, GCP keys disabled per the policy `†`; workload identity federation planned | partial † | reviewer inventory `†` | shared | the long-lived AWS CLI key is still in use for probes; WIF design is G1 item 11 |
| P11.4 | Each actor has its own signing key; keys in a managed key service where possible; issuance, rotation, revocation recorded as signed events | KMS ML-DSA key for the log (S1), per-actor software keys for the demo directory (D4) | partial | `T:kms`, `T:ledger/events` | shared | no rotation or revocation events; the Human Principal's key does not exist |
| P11.5 | Algorithm agility: signed records carry an algorithm label and verification dispatches on it | council events carry a signed `alg` label and verify through a registry | partial | `T:council/algorithm` (a1-a6) | ours | other event families (ledger events, approvals, checkpoints) do not sign an algorithm label; only one real ML-DSA parameter set exists in `entropa-core` |
| P11.6 | Secret scanning on every repository (CI and before any push; push protection on); a finding is read before allowlisting and each entry carries its reason | gitleaks in `C`, `.gitleaks.toml` with a reason per entry | partial | `S:public-preflight.sh`, `S:secret-scan.sh` | ours | no push protection (no hosted remote); only this repository is scanned by this tooling |
| P11.7 | Revoking or deleting a credential follows the hard rule; disabling (reversible) comes first | hook D1, D2, S1; approvals class `credentials_change` | implemented (process) | `T:hook/rules_matrix`, `T:approvals/flow` | process | none known |

## 14. P12 Training and awareness
| ID | MUST (short) | Mechanism and evidence | Status | Proving test | Owner | Gap |
|---|---|---|---|---|---|---|
| P12.1 | Every actor works under a written rule pack before starting; for agents the pack is versioned and its hash recorded | the project rules files and standing orders for the team; the hash-pinned rules artifact for cloud agents (design S13a, `rules_hash` in decisions) | partial | repo files; none for agents | process | the agent rule pack is not written; `rules_hash` not built |
| P12.2 | Hard rules restated at each session start and enforced in code | the project rules at session start; permission rules and the enforcing hook | implemented | `T:hook`, `.claude/settings.json` | ours | none known |
| P12.3 | Every incident, near miss and finding becomes a lesson and, where testable, a red test or rule; lessons reviewed at the monthly retrospective | `a project record (not published)` entries; stage red tests | partial | `a project record (not published)` | process | the monthly retrospective is not running |
| P12.4 | New agents get an onboarding checklist | none | planned | none | process | not written |
| P12.5 | The Human Principal is told plainly what each control does and does not do, in short written form | "honest limits" sections of the designs; stage reports; this map | implemented (process) | docs | process | a one-page plain-language summary of the controls is a deliverable still to write |
| P12.6 | Awareness material uses role names, contains no secrets or personal data, and is reviewed before publication | static scans for internal names in the pure crates and the bundle; the publication gate (planned) | partial | `T:council/static_checks` (g3), `T:explorer/static_checks` (s4), `T:ledger/static_checks` | ours | the book and the website are not scanned; publication review gate planned |

## 15. Coverage by framework (category level, from the policies' own "Supports" lines)
**HIPAA Security Rule** (45 CFR 164 Subpart C; standard names read from the eCFR renderer on 2026-10-22 [https://www.ecfr.gov/api/renderer/v1/content/enhanced/current/title-45?part=164&subpart=C]; no regulatory text is reproduced):
| Standard | Policies that map to it | Honest remark |
|---|---|---|
| 164.306 General rules | P0 | |
| 164.308(a)(1) Security management process | P0, P2, P4, P5, P7 | risk register (P7.1) not written |
| 164.308(a)(2) Assigned security responsibility | P0, P1, P3 (the Human Principal is the owner role of every policy) | **no policy states the assignment as a MUST**; add to P3 or P7 |
| 164.308(a)(3) Workforce security | P3 | solo human plus agents; stated limit P3.6 |
| 164.308(a)(4) Information access management | P3, P11 | |
| 164.308(a)(5) Security awareness and training | P12 | |
| 164.308(a)(6) Security incident procedures | P6 | runbook and drill planned |
| 164.308(a)(7) Contingency plan | P9.5 (backups, restore) only | **no policy covers data backup plan, disaster recovery, emergency mode**; a contingency policy is missing |
| 164.308(a)(8) Evaluation | P7, P8 | |
| 164.308(b)(1) Business associate contracts | P10 | n/a while all data is synthetic |
| 164.310(a)(1) Facility access controls | none | **no policy**; inherited from the cloud providers' data centres for cloud assets; the Human Principal's workstation is ours |
| 164.310(b), (c) Workstation use, workstation security | none | **no policy**; the working PC (disk encryption, screen lock, updates) is ours and not covered |
| 164.310(d)(1) Device and media controls | P9 (disposal, media re-use) | backups on a laptop and a Gitea host are media |
| 164.312(a)(1) Access control | P1, P3, P11 | |
| 164.312(b) Audit controls | P4 | |
| 164.312(c)(1) Integrity | P1, P4, P8 | |
| 164.312(d) Person or entity authentication | P1, P11 | phishing-resistant MFA is a stated gap |
| 164.312(e)(1) Transmission security | P2, P9.4 | CBOM pending |
| 164.314(a)(1) Business associate arrangements | P10 | n/a for now |
| 164.316(a), (b)(1) Policies, documentation | P7, P9.3 | six-year retention table not yet written |
**HITRUST CSF, NIST AI RMF 1.0 and its generative AI profile, ISO/IEC 42001, the EU AI Act, the IAPP AIGP body of knowledge:** the policies cite them by function or category only. NIST AI RMF functions (GOVERN, MAP, MEASURE, MANAGE) are touched by P0-P12 (GOVERN: P1, P3, P5, P10, P12; MAP: P5, P7, P9; MEASURE: P4, P5, P7; MANAGE: P0, P4, P5, P6, P8, P9, P11). The category-level coverage check against the primary sources, the AIGP domain names and the HITRUST reference scope is **not done in this version** (it needs the owner's HITRUST scope and a reading of the primary sources listed in the reviewer's `docs/GOVERNANCE-SOURCES.md`); **this is a planned S14a deliverable, not a result**.

## 16. Gap register (consolidated)
- **G-A Human Principal's own signing key** (P1.6, P3.4, P3.M6, P5.4, P11.4): hard-rule decisions cannot be made positively until it exists (council D3: +$1/month, "not now").
- **G-B Runtime and public surfaces not scanned** (P0.2, P0.4, P4.5): no log scan, no public-page scan, no explorer front end.
- **G-C Not deployed, so not demonstrable** (P1.1, P1.5, P2.5, P4.2, P4.6, P5.8, P7.3): witness, public ledger, council scheduler, agents.
- **G-D Documents not yet written** (P3.6, P5.5, P6.3, P7.1, P7.5, P9.3, P12.4): transparency statement, model cards and impact assessments, incident runbook, risk register, retention table, onboarding checklist.
- **G-E Kill switch, drill, restore test never run** (P5.7, P6.7, P9.5): G1 items 5 and 8.
- **G-F Process controls with no tooling** (P0.1, P1.4, P8.1-P8.3, P8.7): they rest on discipline and dated records.
- **G-G Source-control controls not in place** (P8.4, P11.6): no hosted remote with rulesets, no push protection.
- **G-H Cloud configuration not verified by the author** (P1.2, P4.4, P10.5, P11.2, P11.3): evidence is in the reviewer's repository.
- **G-I Algorithm agility only on council events** (P11.5).
- **G-J Public wording not scanned** (P1.4, P10.1, P12.6).
- **G-K Recurring reviews not scheduled** (P7.4, P7.5, P10.2, P10.7, P12.3).
- **G-L Missing HIPAA-structure coverage** (section 15): assigned security responsibility, the contingency plan, physical safeguards (workstation).
- **G-M Hook-audit chain-head not anchored in the ledger** (P4.3).

## 17. Proposed tests and scripts to close the testable gaps (each red first, one small stage S14b)
- **T-A** a stage-report check that the P0 question is answered (a line in the report template, then a script over `a project record (not published)`).
- **T-B** a forbidden-wording scan over public copy (the website, the explorer pages, the book drafts): "compliant" and "certified" without an "aligned with / mapped to" context fail.
- **T-C** a conflicting-role test: the directory and the gate refuse one key holding two roles; the matrix of P3 as data with a test per row.
- **T-D** a `hook.anchored` event: the hook audit's chain-head hash anchored in the ledger, verified by `S:verify-hook-audit.sh`.
- **T-E** a repository guard: no crate except the (future) agent crate depends on a model or cloud SDK.
- **T-F** a script that every stage row in `docs/EVIDENCE-INDEX.md` names an existing red-evidence file.
- **T-G** a commit check: a commit touching a file under an accepted stage's `tests/` must carry a reason line.
- **T-H** a runtime log canary scan harness (feeds a canary through the hook and the event writers and scans every output).
- **T-I** an `actor.revoke` / rotation event with the replay rule "revoked at index N cannot sign after N" proven end to end.
- **T-J** a restore drill test (rebuild a tenant's state from ledger events, compare the manifest hash) once S13b/c exist.

**Status after stage S14b (2026-10-22, branch `rerust-s14b-controls-tests`):**
| Test | Status | Proof |
|---|---|---|
| T-A | done (script, red first); the cutoff is 2026-10-23 because the P0 question became a review rule on 2026-10-21/22 and the lines before it are exempt | `scripts/tests/governance-checks.sh` (p0 cases); real-repo run in docs/evidence/s14b-real-repo.txt |
| T-B | done (script, red first); first real run found 17 lines on the public pages that use "certified" or "certification" outside a negating or aligned-with context (docs/evidence/s14b-real-repo.txt); the one earned credential name, "AWS Certified", is on `docs/wording-allow.txt` (the owner's statement); the other 17 lines are the owner's stated work-history facts about former employers and credentials, allow-listed as exact lines with the reason recorded (pages not edited); the scan stays strict for everything else, and the real-repo run is now clean | same script |
| T-C | done in code (red first, bite shown): `Directory::try_add` refuses a second identity for a key | `T:approvals/one_role` (c1-c4), docs/evidence/s14b-tc-red.txt, s14b-tc-bite.txt, s14b-tc-green.txt; callers still use `add` (not changed here) |
| T-D | not started: needs a new ledger event type and a hook-side anchoring step; its own stage | none |
| T-E | done (script, red first); no model SDK in any crate today | `sdk` cases; real run clean |
| T-F | done (script, red first); every file the evidence index names exists | `evidence` cases; real run clean |
| T-G | done (script, red first); not wired into check.sh because older history has changed tests without a reason line; use `governance-checks.sh testchange . <base>..HEAD` per stage | `testchange` cases |
| T-H | not started: needs a runtime log harness (hook plus event writers) | none |
| T-I | not started: needs an `actor.revoke` event type; the replay rule itself exists (`revoked_at`) | none |
| T-J | not started: needs S13b/c | none |
Bite evidence (each check fails when deliberately broken): docs/evidence/s14b-bite.txt. T-D, T-H, T-I and T-J stay in the gap register (G-M, G-B, P3.5, G-E); I did not claim them.

## 18. Could not verify (box)
- **Cloud configuration** (CloudTrail, GCP audit logs, IAM roles, MFA, budgets, key retirement): I read none of it; rows marked † repeat the policies' own mechanism lines and the reviewer's inventories.
- **HITRUST CSF structure and the licensed shared-responsibility workbooks:** not read for this version; reference scope is the owner's decision.
- **NIST AI RMF 1.0, its generative AI profile, ISO/IEC 42001, the EU AI Act, the AIGP body of knowledge, MITRE ATLAS, OWASP GenAI and the other sources of the S14a reading list:** not read in this version; no category-level claim is made beyond the function names the policies already cite.
- **Provider eligibility lists:** taken from the reviewer's check of 2026-10-21; re-check quarterly.
- **The proving tests named here were not re-run for this document** except through the stage gates that produced them; each row names the command to re-run.

## 19. Decisions for the reviewer and the owner
- **D1 Status vocabulary and the † marker** as defined in section 1 (recommended).
- **D2 HITRUST reference scope: DECIDED by the owner (2026-10-22), see section 20.** Per platform, aligned with the shape only; no requirement counts until confirmed from HITRUST's public materials; no coverage claim beyond that.
- **D3 Missing policy coverage** (section 15): add short policies or MUST statements for assigned security responsibility, the contingency plan (backup, disaster recovery, emergency mode) and workstation / physical safeguards for the working PC (recommended: yes, as P13 and additions to P3 and P9).
- **D4 Proposed tests T-A to T-J** as one small stage S14b, red first (recommended).
- **D5 Who verifies the † rows:** the reviewer or the owner with a read-only look at the cloud consoles, recorded as dated lines (recommended; I run no cloud command).
- **D6 Publication:** this map stays internal; a public version would drop the † and gap detail only with the owner's approval and the publication gate.

## 20. Scope of the alignment statement (the owner's decision, relayed by the reviewer 2026-10-22; replaces open decision D2)
**Required wording in every document that mentions HITRUST:** "aligned with the shape of HITRUST e1/i1; aware of and following HITRUST's usage terms (licensed material never reproduced); not assessed, not certified." **No requirement counts per level appear in any text** until they are confirmed from HITRUST's own public materials. "Shape" means the structure of essentials and implemented-and-evidenced controls, not a claim to meet any requirement list.
| Platform or area | Depth of the alignment | What it covers |
|---|---|---|
| Baseline, everywhere | e1-style essentials + HIPAA Security Rule safeguards + policies P0-P12 | every row of sections 2-14 of this map |
| AWS | deepest: i1-style subset | clinic data path, ledger signer (KMS), explainer |
| GCP | deep: i1-style | public explorer and bank data paths |
| Azure | light | witness only; out of scope after 2026-11-17 once its evidence is captured |
| GitHub and team tooling | in the baseline | repository, hook, agents' tool use |
Rule of inheritance unchanged (section 1): ours by default; inherited only where the provider's inheritance is full; shared where partial, with the customer-side remainder written down. The licensed inheritance workbooks are read in place and never copied.

## 21. Pipeline layout sketch (doc only; the owner approved the layout 2026-10-22; nothing is built, no workflow changed)
- **One workspace repository, one pipeline per module group, path-filtered.** Each group has a thin workflow that triggers only on its paths and calls one shared reusable workflow (`workflow_call`) with the group's package list as input; one integration pipeline runs the whole workspace on pushes to the integration branch and before a release.
| Group | Paths that trigger it | Packages |
|---|---|---|
| core | `crates/core/**`, `crates/kms/**` | entropa-core, entropa-kms |
| gates | `crates/approvals/**`, `crates/policy/**`, `the agent guard (not published)**` | entropa-approvals, entropa-policy, the agent guard |
| council | `crates/council/**`, `crates/synthetic/**`, `crates/ledger/**` | entropa-council, entropa-synthetic, entropa-ledger |
| edge | `crates/explorer/**`, `crates/mcp/**`, `crates/witness/**` | entropa-explorer, entropa-mcp, entropa-witness |
| governance | `docs/**`, `scripts/**`, `policies/**` | the script tests, the preflight, `governance-checks.sh` |
- **The shared template runs:** fmt, clippy `-D warnings`, tests (default and all features), doc, deny, audit, and the group's own extra steps (mutation nightly, fuzz smoke); the integration pipeline adds the public-readiness preflight and the SBOM. A change to `Cargo.toml`, `Cargo.lock`, `deny.toml` or `rust-toolchain.toml` triggers every group.
- **Constraints carried from the policies:** actions pinned by commit hash (P8.4), no long-lived cloud keys (OIDC, P11.3), `--locked` builds, no deploy step before Gate G1. Where it is testable it is tested red first in S6: a test that every group workflow calls the shared workflow, that each package appears in exactly one group, and that the trigger paths cover every crate directory.
- **Move to `entropa-policies` at publication:** `docs/policies`, `docs/CONTROLS-MAP.md`, the evidence index and later audit reports are written so the move is a copy; evidence references use `repo@tag-or-commit`. No new repository is created before Gate G1 and the owner's word.
