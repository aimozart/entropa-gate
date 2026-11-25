# ARCHITECTURE-CEDAR: a Cedar policy gate combined with the approvals gate (`entropa-policy`)
Status: **design only, no code** (stage S4a, 2026-10-21). A proposal for the reviewer and the owner. Items I could not confirm are marked **UNVERIFIED**; decisions are in section 12.

## 1. Purpose
Two different questions guard an action:
1. **Policy:** may *this principal* perform *this class of action* on *this kind of resource* in *this context*? Static rules, default deny. This is what Cedar does, and what Amazon Bedrock AgentCore Policy uses to guard agent tool calls.
2. **Evidence:** is there a **human sign-off on record** for *exactly this* action? Dynamic evidence in the Entropa log. This is the approvals gate (`entropa-approvals`, S3).
S4 combines them so that an action runs only if the policy permits it **and**, for guarded classes, the evidence exists. Hard-rule classes (delete, spend, publish, credentials_change) stay owner-only: nothing in a policy file can weaken that, because the guard is also fixed in code.

## 2. Facts about Cedar and AgentCore Policy (read 2026-10-21)
- Cedar authorization (https://docs.cedarpolicy.com/auth/authorization.html): a request is allowed only if a `permit` policy is satisfied; a satisfied `forbid` overrides any `permit`; otherwise the decision is Deny. The response carries the decision plus the determining policies. **A policy that errors during evaluation is skipped** (it does not cause a deny; its id and error appear in the diagnostics). This matters: section 6 makes errors fail closed.
- Cedar terminology (https://docs.cedarpolicy.com/overview/terminology.html): principals, actions and resources are entities (`User::"jane"`); actions are defined in the schema; `context` carries transient request details.
- Rust crate `cedar-policy` 4.14.0, Apache-2.0, rust-version 1.89 (checked with `cargo info` today; the workspace toolchain is 1.99.1).
- AgentCore Policy (https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html): a policy engine stores and evaluates Cedar policies for every tool call through an AgentCore Gateway; it "enforces default-deny and forbid-wins semantics automatically"; principals are `AgentCore::OAuthUser` or `AgentCore::IamEntity`; the schema is generated from the gateway's tool definitions and policies are validated against it when associated; automated reasoning flags policies that always allow or always deny. A search result (not the primary page) says the default engine mode is `LOG_ONLY` (evaluate and trace, do not enforce) and `ENFORCE` blocks; I did not read that on the primary page (UNVERIFIED). The same page describes *temporal* policies (written in Dogwood, a Cedar-compatible language) that can require "a prior approval" in the same session. We use plain Cedar only (D9).

## 3. Entity model and schema
| Cedar | Entropa |
|---|---|
| principal `Actor::"<key id>"` | the 16-hex key id from the actor directory; attributes `role` ("human", "ai", "service"), `has_key` (bool) |
| action `Action::"<class>"` | the eight approval classes (`delete`, `spend`, `publish`, `merge`, `deploy`, `direction`, `policy_change`, `credentials_change`) plus non-guarded ones: `read_log`, `append_record`, `call_tool` (D1) |
| resource `Subject::"<subject hash>"` | the exact thing acted on; attribute `kind` (command, file, resource-list, diff) |
| context | `{ now: long, env: "dev"\|"prod", approval: { state, attested, approver_role } }` |
`approval.state` is one of `none`, `pending`, `denied`, `expired`, `used`, `approved`, `attestation_only`, derived from the approvals gate result (section 4). A hand-written schema (`policies/entropa.cedarschema`) fixes these types; every policy is validated against it at load (strict validation), as AgentCore does with its generated schema (D7).

## 4. How the two gates combine
Evaluation order for one request (principal, action class, subject hash, context facts):
1. **Approvals first:** `check(state, class, subject_hash, now, policy)` from `entropa-approvals` gives Allowed (with approver and `attested`) or Blocked(reason). The result is summarised into `context.approval`.
2. **Cedar:** authorize with that context. Policies can condition on it, which is the plain-Cedar form of AgentCore's "requires a prior approval" pattern.
3. **Code guard (not overridable by policy text):** for the hard-rule classes the final answer is Allow only if Cedar allowed **and** the approvals gate answered Allowed with `attested == false`. For `direction`, an attested approval may satisfy the guard. A Cedar `permit` can therefore never open a hard-rule class without a the owner-keyed approval.
4. **Final** = Cedar Allow AND guard satisfied; any Cedar diagnostic error, schema mismatch or invalid request is **Deny** (fail closed, section 6).
Decision table (guarded = a class whose policy requires evidence; hard = hard-rule class):
| Cedar | Approvals gate | Class | Final |
|---|---|---|---|
| Deny | any | any | **Deny** (policy) |
| Allow | any | not guarded (`read_log`, `append_record`, `call_tool`) | **Allow** |
| Allow | Allowed, not attested | guarded or hard | **Allow** |
| Allow | Allowed, attested | `direction` | **Allow** (labelled attested) |
| Allow | Allowed, attested | hard, or any class except `direction` | **Deny** (`attestation_not_accepted`) |
| Allow | Blocked(any) | guarded or hard | **Deny** (carries the gate reason) |
| error | any | any | **Deny** (`policy_error`) |

## 5. Illustrative policies (syntax to be validated by the crate in S4b: UNVERIFIED until then)
```cedar
// anyone may read the log
permit(principal, action == Action::"read_log", resource);
// AI and service principals can never delete, spend, publish or change credentials
forbid(principal, action in [Action::"delete", Action::"spend", Action::"publish", Action::"credentials_change"], resource)
  unless { principal.role == "human" };
// a deploy needs an approval on record
permit(principal, action == Action::"deploy", resource)
  when { context.approval.state == "approved" && !context.approval.attested };
// production is closed to attested approvals
forbid(principal, action, resource) when { context.env == "prod" && context.approval.attested };
```
Policies live in `policies/*.cedar` in the repo; the hook (S2h) already treats protected files as ask, and `policies/` joins that list.

## 6. Fail-closed rules
- The engine refuses to start (every decision is Deny) if the schema or any policy fails to parse or validate, if the policy set is empty, or if limits are exceeded (policy text over 256 KiB, more than 256 policies: proposals).
- Cedar skips erroring policies; we **do not**: any error entry in the diagnostics of a request makes the final decision Deny with reason `policy_error` and the erroring policy ids.
- Unknown action class, unparsable entity id, oversize id (over 128 characters) or a context that does not match the schema: Deny, never a panic, never an echo of the offending value.
- **Role source (S4d, ADR 0019; implemented deviation from the first design).** `principal.role` and `has_key` come only from the signed actor directory. The production constructor is `Engine::new_bound(schema, policies, directory)`; an unknown principal is Deny (`invalid_request`). The constructors that trust `role` and `has_key` from the request (`Engine::new`, `with_directory`) exist only with the cargo feature `trust-request-fields`, which is off by default and enabled only by the crate's own tests (self dev-dependency) and fuzz crate; `tests/feature_guard.rs` checks that no other manifest turns it on. The request fields stay in the `Request` struct and are ignored by the bound engine.
- Observe mode (the analogue of AgentCore's `LOG_ONLY`): the same decision is computed and recorded with `enforced: false`, and the caller is told to allow; enforce mode returns the decision to act on.

## 7. Decision records (reuse of the approval record design)
Every decision is written to the Entropa log as a data-minimal record labelled `policy.decision`, signed by the policy engine's own service key: `{v, actor key id, action class, subject hash, cedar decision, determining policy ids, approval summary (state, attested), final, enforced, policy_set_hash, ts}`. `policy_set_hash` is BLAKE3 over the canonical policy and schema text, so a decision shows which policies were in force. No free text, no conversation, no secrets (same strict decoder rules as approvals).

## 8. Threats
| Id | Threat | Mitigation |
|---|---|---|
| P1 | Policy file tampering | protected-file ask in the hook, `policy_set_hash` in every decision, files in the repo with review |
| P2 | Principal spoofing (a caller claims another key id) | principal ids come from verified signatures (approvals) or from the hook's identity, never from tool arguments |
| P3 | Stale or replayed approval fed as context | the context is computed fresh from the replayed log at decision time; approvals are single-use |
| P4 | Entity id injection (quotes, escapes) into the request | ids are validated against `[0-9a-f]` patterns before building entities; Cedar entity UIDs are constructed through the API, never by string concatenation |
| P5 | A permissive policy opens a hard-rule class | the code guard (section 4.3), the `forbid ... unless role == "human"` policy, and test C6 |
| P6 | Cedar skips an erroring policy and a permit remains | errors make the final decision Deny |
| P7 | Engine unavailable or misconfigured | refuse to start; callers treat "no decision" as Deny for guarded classes |
| P8 | Omission: an action runs without asking the engine | cannot be proven absent by the ledger; mitigation is the hook (blocks classes until the gate allows) and witnesses (S5) |

## 9. AgentCore Policy mapping (SAP-C03 notes)
| AgentCore Policy | Here | What to take from it for the exam (my reading; verify against current AWS docs before relying) |
|---|---|---|
| Policy engine attached to a Gateway | `entropa-policy` engine called by the hook/MCP layer | a central policy decision point in front of tool calls |
| Gateway target tools | action classes and tool names | one action per tool; least-privilege per tool |
| Principal types (OAuth user, IAM entity) | `Actor` key ids (IAM ARNs when deployed on AWS) | identity propagation to the decision point |
| Schema generated from tool definitions; validation at association | hand-written schema, strict validation at load | validate policies before deployment |
| Default deny, forbid wins | Cedar semantics, identical | same shape as IAM policy evaluation (explicit deny, then allow, else implicit deny): UNVERIFIED here, from general knowledge |
| `LOG_ONLY` vs `ENFORCE` | observe vs enforce | roll out in monitor-only mode before enforcing |
| Temporal policy "requires a prior approval" | approvals gate summarised into `context.approval` | human-in-the-loop as a policy input |
| Guardrails, natural-language policy authoring | not used | out of scope |
| KMS key inaccessible makes all decisions Deny | fail closed on any engine fault | fail closed |
Deploying a real AgentCore policy engine is not part of S4 (section 10).

## 10. FinOps
- S4 is **$0**: local library, no cloud resource, no network (`cedar-policy` is a Rust crate; adding it is a build-time dependency only).
- AgentCore Policy pricing is **not verified** and nothing in S4 creates an AgentCore resource. If a later stage deploys one in a sandbox account to compare behavior, the cost rule applies: price it from the AWS pricing pages first, record it in the cost notes with the teardown command, wait for the owner's go, tag `project=entropa`, delete it the same day (deletion needs explicit approval).

## 11. Test plan (S4b writes these red; S4c makes them green)
| Id | Case | Expected |
|---|---|---|
| C1 | valid schema and policies load; invalid policy text; policy naming an unknown action; empty policy set | load ok / error naming the problem / validation error / engine loads and denies everything |
| C2 | default deny with no matching permit; forbid beats permit | Deny / Deny with the forbid id in the determining policies |
| C3 | a policy that errors at runtime (missing attribute without `has`) | final Deny, reason `policy_error`, erroring id reported |
| C4 | AI principal asks `delete`; human asks `delete` with and without approval | Deny / Allow only with a non-attested approval |
| C5 | `deploy` permit that requires `context.approval.state == "approved"` over every approval state | Allow only for `approved` |
| C6 | a deliberately permissive Cedar permit for `delete`; attested approval for `delete`; attested approval for `direction` | Deny (code guard) / Deny `attestation_not_accepted` / Allow attested |
| C7 | full decision table (section 4) as a table-driven test | every row as stated |
| C8 | decision record: golden vector from an independent generator, signature, append to the log, replay, no free text, strict decoder rejects extras | as stated |
| C9 | determinism: same inputs give the same decision and the same ordered determining policy ids | equal |
| C10 | hostile entity ids (quotes, backslashes, unicode, 10,000 characters, NUL), oversize policy text, 1,000 policies | Deny or load error, no panic, value never echoed |
| C11 | observe mode | same decision, `enforced: false` |
| P1 | proptest: final Allow implies Cedar Allow and (class not guarded, or approvals gate Allowed; hard-rule additionally not attested) | invariant holds over 256 cases |
| F1 | fuzz targets: policy text parser, request builder | no panic |
| N1 | static guards | no network, process spawn, unsafe, file writes; policies come from strings |

## 12. Decisions for the reviewer and the owner
- **D1** the action vocabulary: the eight approval classes plus `read_log`, `append_record`, `call_tool`.
- **D2** combination: approvals summarised into the Cedar context **plus** the code guard for hard-rule classes (proposal), versus two independent decisions ANDed.
- **D3** policies and schema as files under `policies/`, protected by the hook (ask).
- **D4** any Cedar diagnostic error makes the decision Deny (proposal) rather than Cedar's skip-the-policy default.
- **D5** decision records labelled `policy.decision`, signed by a dedicated service key; development key local, production key in KMS only after the owner approves the price.
- **D6** observe and enforce modes as in section 6.
- **D7** hand-written schema now; generate it from the MCP tool definitions later.
- **D8** a sandbox AgentCore Policy comparison in a later, separately priced stage, or not at all.
- **D9** plain Cedar only; no Dogwood.
- **D10** new dependency `cedar-policy` 4.14.0 (Apache-2.0): needs an ADR and a `cargo deny` licence check in S4b.
