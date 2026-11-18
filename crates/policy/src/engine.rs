//! The engine: load and validate a schema and policy set, then decide.

use crate::{Action, Decision, Env, Mode, Outcome, PolicyError, Reason, Request, RoleName};
use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, Entity, EntityId, EntityTypeName,
    EntityUid, PolicyId, PolicySet, Request as CedarRequest, RestrictedExpression, Schema,
    ValidationMode, Validator,
};
use entropa_approvals::{ActionClass, BlockReason, Directory, GateDecision, Role};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

const MAX_SCHEMA_BYTES: usize = 64 * 1024;
const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_POLICIES: usize = 256;
const MAX_TOKEN: usize = 64;

/// The policy engine: a validated schema and policy set, optionally bound to the signed actor
/// directory (then roles come only from the directory, never from the request).
pub struct Engine {
    schema: Schema,
    policies: PolicySet,
    display_ids: HashMap<PolicyId, String>,
    action_entities: Entities,
    hash: String,
    directory: Option<Directory>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("hash", &self.hash)
            .field("policies", &self.display_ids.len())
            .finish_non_exhaustive()
    }
}

fn token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TOKEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Engine {
    /// Load and validate a schema and a policy set (strict validation). Limits: schema 64 KiB,
    /// policies 256 KiB and 256 policies; every policy id must be a short token.
    ///
    /// The engine is bound to the signed actor directory: a principal's role and key status are
    /// read from the directory only (request fields are ignored), and an unknown principal is denied.
    pub fn new_bound(
        schema: &str,
        policies: &str,
        directory: Directory,
    ) -> Result<Engine, PolicyError> {
        let mut e = Self::build(schema, policies)?;
        e.directory = Some(directory);
        Ok(e)
    }

    /// Like [`Engine::new_bound`] but trusting `role` and `has_key` from the request. Only with
    /// the cargo feature `trust-request-fields` (tests and fuzzing; ADR 0019).
    #[cfg(feature = "trust-request-fields")]
    pub fn new(schema: &str, policies: &str) -> Result<Engine, PolicyError> {
        Self::build(schema, policies)
    }

    fn build(schema: &str, policies: &str) -> Result<Engine, PolicyError> {
        if schema.len() > MAX_SCHEMA_BYTES {
            return Err(PolicyError::Limit(
                "schema text is larger than 64 KiB".into(),
            ));
        }
        if policies.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::Limit(
                "policy text is larger than 256 KiB".into(),
            ));
        }
        let (schema_parsed, _warnings) = Schema::from_cedarschema_str(schema)
            .map_err(|e| PolicyError::Parse(format!("schema: {e}")))?;
        let pset = PolicySet::from_str(policies)
            .map_err(|e| PolicyError::Parse(format!("policies: {e}")))?;
        if pset.policies().count() > MAX_POLICIES {
            return Err(PolicyError::Limit("more than 256 policies".into()));
        }
        let mut display_ids = HashMap::new();
        for p in pset.policies() {
            let shown = p
                .annotation("id")
                .map_or_else(|| p.id().to_string(), str::to_string);
            if !token_ok(&shown) {
                return Err(PolicyError::Validation(
                    "a policy id must be a short token of A-Za-z0-9._:/-".into(),
                ));
            }
            display_ids.insert(p.id().clone(), shown);
        }
        let result = Validator::new(schema_parsed.clone()).validate(&pset, ValidationMode::Strict);
        if !result.validation_passed() {
            let first = result
                .validation_errors()
                .next()
                .map_or_else(|| "validation failed".to_string(), |e| e.to_string());
            return Err(PolicyError::Validation(first));
        }
        let action_entities = schema_parsed
            .action_entities()
            .map_err(|e| PolicyError::Validation(format!("actions: {e}")))?;
        let mut h = blake3::Hasher::new();
        h.update(b"entropa-policy-set-v1\0");
        for text in [schema, policies] {
            h.update(&(text.len() as u64).to_be_bytes());
            h.update(text.as_bytes());
        }
        Ok(Engine {
            schema: schema_parsed,
            policies: pset,
            display_ids,
            action_entities,
            hash: hex::encode(h.finalize().as_bytes()),
            directory: None,
        })
    }

    /// Bind the engine to the signed actor directory: a principal's role and key status are then
    /// read from the directory only (request fields are ignored), and unknown principals are denied.
    #[cfg(feature = "trust-request-fields")]
    pub fn with_directory(mut self, directory: Directory) -> Engine {
        self.directory = Some(directory);
        self
    }

    /// BLAKE3 over the schema and policy text, so a decision shows which policies were in force.
    pub fn policy_set_hash(&self) -> String {
        self.hash.clone()
    }

    fn shown(&self, id: &PolicyId) -> String {
        self.display_ids
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_string())
    }

    /// Decide: approvals result into the Cedar context, Cedar, then the code guard.
    pub fn decide(&self, req: &Request, gate: &GateDecision, mode: Mode) -> Decision {
        let mut d = self.decide_enforced(req, gate);
        d.enforced = mode == Mode::Enforce;
        d
    }

    fn deny(reason: Reason, state: &str, attested: bool) -> Decision {
        Decision {
            outcome: Outcome::Deny,
            cedar: None,
            determining: vec![],
            error_policies: vec![],
            reason,
            enforced: true,
            approval_state: state.into(),
            approval_attested: attested,
        }
    }

    fn decide_enforced(&self, req: &Request, gate: &GateDecision) -> Decision {
        let (state, attested) = approval_summary(gate);
        let invalid = || Self::deny(Reason::InvalidRequest, state, attested);
        // role and key status: from the signed directory when bound, else from the request
        let (role, has_key) = match &self.directory {
            Some(dir) => match dir.actors.get(&req.principal) {
                Some(a) => (
                    match a.role {
                        Role::Human => RoleName::Human,
                        Role::Ai => RoleName::Ai,
                        Role::Service => RoleName::Service,
                    },
                    !a.pubkey_hex.is_empty(),
                ),
                None => return invalid(),
            },
            None => (req.role, req.has_key),
        };
        if !lower_hex(&req.principal, 16)
            || !lower_hex(&req.subject_hash, 64)
            || !token_ok(&req.subject_kind)
            || req.now > i64::MAX as u64
        {
            return invalid();
        }
        let Ok(cedar_req) = self.cedar_request(req, role, has_key, state, attested, gate) else {
            return invalid();
        };
        let entities = match self.entities(req, role, has_key) {
            Ok(e) => e,
            Err(()) => return invalid(),
        };
        let response = Authorizer::new().is_authorized(&cedar_req, &self.policies, &entities);
        let mut determining: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| self.shown(id))
            .collect();
        determining.sort();
        let mut error_policies: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| match e {
                cedar_policy::AuthorizationError::PolicyEvaluationError(p) => {
                    self.shown(p.policy_id())
                }
            })
            .collect();
        error_policies.sort();
        error_policies.dedup();
        let make = |outcome, cedar, reason, determining, error_policies| Decision {
            outcome,
            cedar,
            determining,
            error_policies,
            reason,
            enforced: true,
            approval_state: state.into(),
            approval_attested: attested,
        };
        if !error_policies.is_empty() {
            return make(
                Outcome::Deny,
                None,
                Reason::PolicyError,
                determining,
                error_policies,
            );
        }
        let cedar = if response.decision() == CedarDecision::Allow {
            Outcome::Allow
        } else {
            Outcome::Deny
        };
        // guarded actions need the approvals gate, whatever Cedar says
        if let Action::Class(class) = req.action {
            match gate {
                GateDecision::Blocked(b) => {
                    return make(
                        Outcome::Deny,
                        Some(cedar),
                        Reason::GateBlocked(*b),
                        determining,
                        vec![],
                    )
                }
                GateDecision::Allowed { attested: true, .. }
                    if class != ActionClass::Direction || class.is_hard_rule() =>
                {
                    if cedar == Outcome::Allow {
                        return make(
                            Outcome::Deny,
                            Some(cedar),
                            Reason::AttestationNotAccepted,
                            determining,
                            vec![],
                        );
                    }
                }
                GateDecision::Allowed { .. } => {}
            }
        }
        if cedar == Outcome::Deny {
            return make(
                Outcome::Deny,
                Some(cedar),
                Reason::CedarDeny,
                determining,
                vec![],
            );
        }
        make(
            Outcome::Allow,
            Some(cedar),
            Reason::Allowed,
            determining,
            vec![],
        )
    }

    fn uid(&self, ty: &str, id: &str) -> Result<EntityUid, ()> {
        let ty = EntityTypeName::from_str(ty).map_err(|_| ())?;
        Ok(EntityUid::from_type_name_and_id(ty, EntityId::new(id)))
    }

    fn entities(&self, req: &Request, role: RoleName, has_key: bool) -> Result<Entities, ()> {
        let role_name = match role {
            RoleName::Human => "human",
            RoleName::Ai => "ai",
            RoleName::Service => "service",
        };
        let actor = Entity::new(
            self.uid("Actor", &req.principal)?,
            HashMap::from([
                (
                    "role".to_string(),
                    RestrictedExpression::new_string(role_name.to_string()),
                ),
                (
                    "has_key".to_string(),
                    RestrictedExpression::new_bool(has_key),
                ),
            ]),
            HashSet::new(),
        )
        .map_err(|_| ())?;
        let subject = Entity::new(
            self.uid("Subject", &req.subject_hash)?,
            HashMap::from([(
                "kind".to_string(),
                RestrictedExpression::new_string(req.subject_kind.clone()),
            )]),
            HashSet::new(),
        )
        .map_err(|_| ())?;
        let both = Entities::from_entities([actor, subject], Some(&self.schema)).map_err(|_| ())?;
        both.add_entities(self.action_entities.iter().cloned(), Some(&self.schema))
            .map_err(|_| ())
    }

    fn cedar_request(
        &self,
        req: &Request,
        _role: RoleName,
        _has_key: bool,
        state: &str,
        attested: bool,
        gate: &GateDecision,
    ) -> Result<CedarRequest, ()> {
        let action = self.uid("Action", req.action.as_str())?;
        let approver_role = match gate {
            GateDecision::Allowed { approver, .. } => match &self.directory {
                Some(dir) => dir
                    .actors
                    .get(approver)
                    .map_or("unknown", |a| match a.role {
                        Role::Human => "human",
                        Role::Ai => "ai",
                        Role::Service => "service",
                    }),
                None => "unknown",
            },
            GateDecision::Blocked(_) => "none",
        };
        let env = match req.env {
            Env::Dev => "dev",
            Env::Prod => "prod",
        };
        let context = Context::from_json_value(
            serde_json::json!({"now": req.now as i64, "env": env, "approval": {"state": state, "attested": attested, "approver_role": approver_role}}),
            Some((&self.schema, &action)),
        )
        .map_err(|_| ())?;
        CedarRequest::new(
            self.uid("Actor", &req.principal)?,
            action,
            self.uid("Subject", &req.subject_hash)?,
            context,
            Some(&self.schema),
        )
        .map_err(|_| ())
    }
}

/// The approval state placed in the Cedar context, and whether it is an attestation.
fn approval_summary(gate: &GateDecision) -> (&'static str, bool) {
    match gate {
        GateDecision::Allowed {
            attested: false, ..
        } => ("approved", false),
        GateDecision::Allowed { attested: true, .. } => ("attestation_only", true),
        GateDecision::Blocked(b) => match b {
            BlockReason::NoRequest | BlockReason::SubjectMismatch => ("none", false),
            BlockReason::Pending => ("pending", false),
            BlockReason::Denied => ("denied", false),
            BlockReason::Expired => ("expired", false),
            BlockReason::AlreadyUsed => ("used", false),
            BlockReason::AttestationNotAccepted => ("attestation_only", true),
        },
    }
}
