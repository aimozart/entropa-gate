//! The scripted scenario catalogue (six scenarios in a fixed cycle). Every decision goes through the
//! real approvals gate and the real Cedar engine via the generator's helpers; nothing is faked.

use crate::event::AgentMeta;
use crate::generator::{Generator, RunSummary};
use crate::store::LedgerStore;
use crate::vocab::{Decision, Handle, Kind, LabelCode, Provider, ReasonCode, Tenant};
use crate::LedgerError;
use entropa_approvals as ap;
use entropa_approvals::ActionClass;
use entropa_policy::Action;

const VALID_FOR_SECS: u64 = 86_400;
const CYCLE: usize = 6;

fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn subject(tenant: Tenant, tag: &str, n: usize) -> String {
    hex::encode(blake3::hash(format!("{}:{tag}:{n}", tenant.as_str()).as_bytes()).as_bytes())
}

impl Generator {
    fn meta(r: u64) -> AgentMeta {
        let (input, output) = (800 + r % 3000, 50 + (r >> 20) % 400);
        AgentMeta {
            provider: Provider::Fake,
            model_id: "amazon.nova-lite-v1:0".into(),
            input_tokens: input,
            output_tokens: output,
            cost_micro_usd: (input * 6 + output * 24) / 100,
        }
    }

    pub(crate) fn scenario<S: LedgerStore>(
        &mut self,
        store: &mut S,
        sum: &mut RunSummary,
        n: usize,
        t: u64,
    ) -> Result<(), LedgerError> {
        let r = mix(self.seed ^ (n as u64).wrapping_mul(0x1234_5679));
        let (bank, clinic, ent) = (
            Tenant::Bigironbank,
            Tenant::Hippagrchealthcare,
            Tenant::Entropa,
        );
        match n % CYCLE {
            0 => {
                let s = subject(bank, "clear", n);
                let f = self.fields(
                    Kind::TxScreened,
                    bank,
                    Handle::AgentBigironbank,
                    t,
                    &s,
                    LabelCode::FraudScreen,
                    Decision::Allow,
                    ReasonCode::WithinLimits,
                    Some(Self::meta(r)),
                );
                self.event(store, sum, Handle::AgentBigironbank, f)?;
            }
            1 => {
                let s = subject(bank, "hold", n);
                let f = self.fields(
                    Kind::TxScreened,
                    bank,
                    Handle::AgentBigironbank,
                    t,
                    &s,
                    LabelCode::FraudScreen,
                    Decision::Hold,
                    ReasonCode::NeedsReview,
                    Some(Self::meta(r)),
                );
                self.event(store, sum, Handle::AgentBigironbank, f)?;
                let req = ap::Event::request(
                    &self.id(Handle::AgentBigironbank),
                    t + 5,
                    ActionClass::Spend,
                    &s,
                    &format!("bigironbank:{n}"),
                    VALID_FOR_SECS,
                );
                let rid = req.request_id.clone();
                self.approval(store, sum, bank, Handle::AgentBigironbank, req)?;
                let ok = ap::Event::approve(
                    &self.id(Handle::OrchestratorAgent),
                    t + 10,
                    &rid,
                    None,
                    None,
                );
                self.approval(store, sum, bank, Handle::OrchestratorAgent, ok)?;
                self.decide(
                    store,
                    sum,
                    bank,
                    Handle::AgentBigironbank,
                    Action::Class(ActionClass::Spend),
                    &s,
                    t + 12,
                )?;
            }
            2 => {
                let s = subject(bank, "escalate", n);
                let f = self.fields(
                    Kind::TxScreened,
                    bank,
                    Handle::AgentBigironbank,
                    t,
                    &s,
                    LabelCode::FraudScreen,
                    Decision::Escalate,
                    ReasonCode::HumanRequired,
                    Some(Self::meta(r)),
                );
                self.event(store, sum, Handle::AgentBigironbank, f)?;
                let req = ap::Event::request(
                    &self.id(Handle::AgentBigironbank),
                    t + 5,
                    ActionClass::Direction,
                    &s,
                    &format!("bigironbank:{n}"),
                    VALID_FOR_SECS,
                );
                let rid = req.request_id.clone();
                self.approval(store, sum, bank, Handle::AgentBigironbank, req)?;
                let basis =
                    hex::encode(blake3::hash(format!("synthetic-basis-{n}").as_bytes()).as_bytes());
                let human = self.id(Handle::HumanPrincipal);
                let ok = ap::Event::approve(
                    &self.id(Handle::OrchestratorAgent),
                    t + 10,
                    &rid,
                    Some(&human),
                    Some(&basis),
                );
                self.approval(store, sum, bank, Handle::OrchestratorAgent, ok)?;
                if self.decide(
                    store,
                    sum,
                    bank,
                    Handle::AgentBigironbank,
                    Action::Class(ActionClass::Direction),
                    &s,
                    t + 12,
                )? {
                    let used = ap::Event::consume(&self.id(Handle::AgentBigironbank), t + 20, &rid);
                    self.approval(store, sum, bank, Handle::AgentBigironbank, used)?;
                }
            }
            3 => {
                let s = subject(clinic, "case", n);
                let f = self.fields(
                    Kind::AgentInvocation,
                    clinic,
                    Handle::AgentHippagrchealthcare,
                    t,
                    &s,
                    LabelCode::CaseReview,
                    Decision::Info,
                    ReasonCode::NeedsReview,
                    Some(Self::meta(r)),
                );
                self.event(store, sum, Handle::AgentHippagrchealthcare, f)?;
                let req = ap::Event::request(
                    &self.id(Handle::AgentHippagrchealthcare),
                    t + 5,
                    ActionClass::Deploy,
                    &s,
                    &format!("hippagrchealthcare:{n}"),
                    VALID_FOR_SECS,
                );
                let rid = req.request_id.clone();
                self.approval(store, sum, clinic, Handle::AgentHippagrchealthcare, req)?;
                let orch = self.id(Handle::OrchestratorAgent);
                let decision = if (n / CYCLE).is_multiple_of(2) {
                    ap::Event::deny(&orch, t + 10, &rid, ap::ReasonCode::TooRisky, None, None)
                } else {
                    ap::Event::approve(&orch, t + 10, &rid, None, None)
                };
                self.approval(store, sum, clinic, Handle::OrchestratorAgent, decision)?;
                if self.decide(
                    store,
                    sum,
                    clinic,
                    Handle::AgentHippagrchealthcare,
                    Action::Class(ActionClass::Deploy),
                    &s,
                    t + 12,
                )? {
                    let used =
                        ap::Event::consume(&self.id(Handle::AgentHippagrchealthcare), t + 20, &rid);
                    self.approval(store, sum, clinic, Handle::AgentHippagrchealthcare, used)?;
                }
            }
            4 => {
                let s = subject(ent, "question", n);
                let f = self.fields(
                    Kind::AgentInvocation,
                    ent,
                    Handle::AgentEntropa,
                    t,
                    &s,
                    LabelCode::AuditQuestion,
                    Decision::Info,
                    ReasonCode::CitedReceipts,
                    Some(Self::meta(r)),
                );
                self.event(store, sum, Handle::AgentEntropa, f)?;
                self.decide(
                    store,
                    sum,
                    ent,
                    Handle::AgentEntropa,
                    Action::ReadLog,
                    &s,
                    t + 2,
                )?;
            }
            _ => {
                let s = subject(ent, "merge", n);
                let req = ap::Event::request(
                    &self.id(Handle::BuilderAgent),
                    t,
                    ActionClass::Merge,
                    &s,
                    &format!("entropa:{n}"),
                    VALID_FOR_SECS,
                );
                let rid = req.request_id.clone();
                self.approval(store, sum, ent, Handle::BuilderAgent, req)?;
                let ok = ap::Event::approve(
                    &self.id(Handle::OrchestratorAgent),
                    t + 10,
                    &rid,
                    None,
                    None,
                );
                self.approval(store, sum, ent, Handle::OrchestratorAgent, ok)?;
                if self.decide(
                    store,
                    sum,
                    ent,
                    Handle::BuilderAgent,
                    Action::Class(ActionClass::Merge),
                    &s,
                    t + 12,
                )? {
                    let used = ap::Event::consume(&self.id(Handle::BuilderAgent), t + 20, &rid);
                    self.approval(store, sum, ent, Handle::BuilderAgent, used)?;
                }
            }
        }
        Ok(())
    }
}
