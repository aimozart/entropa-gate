// Entropa reference policies (docs/ARCHITECTURE-CEDAR.md section 5). Default deny; forbid wins.
// Syntax is validated against policies/entropa.cedarschema by the cedar-policy crate in S4c.

@id("read-log-for-everyone")
permit(principal, action == Action::"read_log", resource);

@id("append-by-keyed-actors")
permit(principal, action == Action::"append_record", resource)
  when { principal.has_key };

@id("tools-for-keyed-actors")
permit(principal, action == Action::"call_tool", resource)
  when { principal.has_key };

@id("hard-rule-actions-need-a-human")
forbid(principal, action in [Action::"delete", Action::"spend", Action::"publish", Action::"credentials_change"], resource)
  unless { principal.role == "human" };

@id("humans-with-approval-do-hard-rule-actions")
permit(principal, action in [Action::"delete", Action::"spend", Action::"publish", Action::"credentials_change"], resource)
  when { principal.role == "human" && context.approval.state == "approved" && !context.approval.attested };

@id("deploy-and-merge-need-an-approval")
permit(principal, action in [Action::"deploy", Action::"merge", Action::"policy_change"], resource)
  when { context.approval.state == "approved" && !context.approval.attested };

@id("direction-by-approval-or-attestation")
permit(principal, action == Action::"direction", resource)
  when { context.approval.state == "approved" || context.approval.state == "attestation_only" };

@id("production-closed-to-attested-approvals")
forbid(principal, action, resource)
  when { context.env == "prod" && context.approval.attested && !(action == Action::"direction") };
