//! The Cedar adapter: the tier policies as Cedar text, loaded strictly and evaluated fail-closed. Default deny: only an explicit `permit` allows. Cedar can only RESTRICT: the tier
//! ceiling in `Gate::decide` is code and runs before this engine. An evaluation error (Cedar skips the policy and reports it) is returned as an error, which the gate turns into a
//! denial. Nothing here reads a clock, a file, the environment or the network.
use crate::{Action, PolicyEngine};
use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request as CedarRequest,
};
use entropa_tokens::Tier;
use std::str::FromStr;

/// The tier policies that ship: default deny, one `permit` per allowed (tier, action). T3 has none (change control is another stage).
pub const TIER_POLICIES: &str = r#"
permit(principal == Tier::"t0", action == Action::"read_corpus", resource);
permit(principal == Tier::"t1", action == Action::"read_corpus", resource);
permit(principal == Tier::"t1", action == Action::"call_model", resource);
permit(principal == Tier::"t2", action == Action::"read_corpus", resource);
permit(principal == Tier::"t2", action == Action::"call_model", resource);
permit(principal == Tier::"t2", action == Action::"call_tool", resource is Tool);
"#;

/// A strict, fail-closed Cedar policy set.
pub struct CedarPolicy {
    set: PolicySet,
    hash: String,
}

fn uid(ty: &str, id: &str) -> Result<EntityUid, String> {
    let ty = EntityTypeName::from_str(ty).map_err(|e| e.to_string())?;
    Ok(EntityUid::from_type_name_and_id(ty, EntityId::new(id)))
}

impl CedarPolicy {
    /// Load a policy set from text. Any parse error refuses the whole set; an empty text is a valid set that denies everything.
    pub fn from_text(text: &str) -> Result<CedarPolicy, String> {
        let set = PolicySet::from_str(text).map_err(|e| format!("policy text: {e}"))?;
        Ok(CedarPolicy {
            set,
            hash: hex::encode(blake3::hash(text.as_bytes()).as_bytes()),
        })
    }
    /// The shipped tier policies.
    pub fn tiers() -> CedarPolicy {
        match CedarPolicy::from_text(TIER_POLICIES) {
            Ok(p) => p,
            // the shipped text is a constant that the tests parse; if it ever did not, an empty set (deny everything) is the only safe fallback
            Err(_) => CedarPolicy {
                set: PolicySet::new(),
                hash: String::new(),
            },
        }
    }
}

impl PolicyEngine for CedarPolicy {
    fn allows(&self, tier: Tier, action: Action, tool: Option<&str>) -> Result<bool, String> {
        let principal = uid("Tier", tier.as_str())?;
        let act = uid("Action", action.as_str())?;
        let resource = match (action, tool) {
            (Action::CallTool, Some(t)) => uid("Tool", t)?,
            _ => uid("Resource", "none")?,
        };
        let req = CedarRequest::new(principal, act, resource, Context::empty(), None)
            .map_err(|e| e.to_string())?;
        let resp = Authorizer::new().is_authorized(&req, &self.set, &Entities::empty());
        if resp.diagnostics().errors().next().is_some() {
            return Err("a policy failed to evaluate".into());
        }
        Ok(resp.decision() == CedarDecision::Allow)
    }
    fn policy_hash(&self) -> String {
        self.hash.clone()
    }
}
