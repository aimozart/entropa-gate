//! The deterministic synthetic scenario generator: the only writer of the public ledger. It drives
//! the real approvals, Cedar policy and witness crates; nothing here fakes a decision.

use crate::event::{encode_event, sign_event, AgentMeta, EventFields};
use crate::keys::{Keys, KEYED};
use crate::store::LedgerStore;
use crate::vocab::{Decision, Handle, Kind, LabelCode, ReasonCode, RoleCode, Tenant};
use crate::LedgerError;
use entropa_approvals as ap;
use entropa_approvals::{
    ActionClass, Actor, AttestationPolicy, BlockReason, Body, Directory, GateDecision, Role,
};
use entropa_core::merkle::{consistency_proof, leaf_hash, Hash};
use entropa_core::transparency_log::{encode_record, TransparencyLog};
use entropa_core::Probe;
use entropa_policy::{Action, Engine, Env, Mode, Outcome, Request, RoleName};
use entropa_witness::{log_id_for, LogConfig, State as WState, StateStore, StoreError, Witness};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

const MAX_SCENARIOS: usize = 10_000;

/// What a generator run produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunSummary {
    /// Records appended.
    pub records: usize,
    /// Checkpoints stored.
    pub checkpoints: usize,
    /// Witness statements stored.
    pub witnesses: usize,
    /// Records per tenant.
    pub by_tenant: BTreeMap<String, usize>,
    /// Records per kind string.
    pub by_kind: BTreeMap<String, usize>,
    /// Actions the policy and approvals gate refused.
    pub refused: usize,
    /// Actions allowed (with a valid approval where one is required).
    pub allowed: usize,
}

/// The witness's own small state store (in memory; the generator is the single writer).
#[derive(Default)]
struct WitnessStore(Mutex<HashMap<String, (WState, u64)>>);

impl StateStore for WitnessStore {
    fn get(&self, log_id: &str) -> Result<Option<(WState, String)>, StoreError> {
        let g = self
            .0
            .lock()
            .map_err(|_| StoreError::Failed("lock".into()))?;
        Ok(g.get(log_id).map(|(s, v)| (*s, v.to_string())))
    }
    fn compare_and_swap(
        &self,
        log_id: &str,
        expected: Option<&str>,
        new: &WState,
    ) -> Result<(), StoreError> {
        let mut g = self
            .0
            .lock()
            .map_err(|_| StoreError::Failed("lock".into()))?;
        let current = g.get(log_id).map(|(_, v)| v.to_string());
        if current.as_deref() != expected {
            return Err(StoreError::Conflict);
        }
        let v = g.get(log_id).map_or(1, |(_, v)| v + 1);
        g.insert(log_id.to_string(), (*new, v));
        Ok(())
    }
    fn record_equivocation(&self, _log_id: &str, _evidence: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

/// The deterministic synthetic scenario generator: the only writer of the public ledger.
pub struct Generator {
    pub(crate) keys: Keys,
    pub(crate) directory: Directory,
    pub(crate) handles: BTreeMap<String, Handle>,
    ids: BTreeMap<Handle, String>,
    pub(crate) seed: u64,
    engine: Engine,
    policy_hash: String,
    log: TransparencyLog,
    registered: bool,
    pub(crate) counter: usize,
    witness: Witness<Arc<WitnessStore>, Probe>,
    witnessed: usize,
    last_ts: u64,
}

fn err<E: std::fmt::Debug>(what: &str) -> impl Fn(E) -> LedgerError + '_ {
    move |_| LedgerError::Invalid(what.to_string())
}

fn role_name(r: Role) -> RoleName {
    match r {
        Role::Human => RoleName::Human,
        Role::Ai => RoleName::Ai,
        Role::Service => RoleName::Service,
    }
}

fn role_code(r: Role) -> RoleCode {
    match r {
        Role::Human => RoleCode::Human,
        Role::Ai => RoleCode::Ai,
        Role::Service => RoleCode::Service,
    }
}

impl Generator {
    /// Build a generator from a public seed and the Cedar schema and policy text.
    pub fn new(seed: u64, schema: &str, policies: &str) -> Result<Generator, LedgerError> {
        let keys = Keys::from_seed(seed)?;
        let mut directory = Directory::new();
        let mut handles = BTreeMap::new();
        let mut ids = BTreeMap::new();
        let human = directory.add_keyless_human(Handle::HumanPrincipal.as_str());
        if let Some(a) = directory.actors.get_mut(&human) {
            a.may_approve = vec![ActionClass::Direction];
        }
        handles.insert(human.clone(), Handle::HumanPrincipal);
        ids.insert(Handle::HumanPrincipal, human.clone());
        for h in KEYED {
            let probe = keys
                .probe(h)
                .ok_or_else(|| LedgerError::Sign("missing demo key".into()))?;
            let (role, approve, attest) = match h {
                Handle::OrchestratorAgent => (
                    Role::Ai,
                    vec![
                        ActionClass::Merge,
                        ActionClass::Deploy,
                        ActionClass::Direction,
                        ActionClass::PolicyChange,
                        ActionClass::Spend,
                    ],
                    vec![human.clone()],
                ),
                Handle::LogSigner | Handle::Generator | Handle::WitnessAzure => {
                    (Role::Service, vec![], vec![])
                }
                _ => (Role::Ai, vec![], vec![]),
            };
            let id = directory.add(Actor {
                pubkey_hex: probe.pubkey_hex(),
                role,
                may_approve: approve,
                may_attest_for: attest,
                revoked_at: None,
            });
            handles.insert(id.clone(), h);
            ids.insert(h, id);
        }
        let engine = Engine::new_bound(schema, policies, directory.clone())
            .map_err(err("policy schema or policies"))?;
        let policy_hash = engine.policy_set_hash();
        let log_probe = keys
            .probe(Handle::LogSigner)
            .ok_or_else(|| LedgerError::Sign("missing log key".into()))?;
        let witness_key = keys
            .probe(Handle::WitnessAzure)
            .ok_or_else(|| LedgerError::Sign("missing witness key".into()))?;
        let witness_signer = Probe::from_signing_key_hex(&witness_key.signing_key_hex())
            .ok_or_else(|| LedgerError::Sign("witness key".into()))?;
        let log_pub = log_probe.pubkey_hex();
        let witness = Witness::new(
            vec![LogConfig {
                log_id: log_id_for(&log_pub),
                pubkey_hex: log_pub,
                allow_first: true,
            }],
            Arc::new(WitnessStore::default()),
            witness_signer,
        )
        .map_err(err("witness configuration"))?;
        Ok(Generator {
            keys,
            directory,
            handles,
            ids,
            seed,
            engine,
            policy_hash,
            log: TransparencyLog::new(),
            registered: false,
            counter: 0,
            witness,
            witnessed: 0,
            last_ts: 0,
        })
    }

    /// The actor directory the generator registers.
    pub fn directory(&self) -> Directory {
        self.directory.clone()
    }

    /// Handle by key id.
    pub fn handles(&self) -> BTreeMap<String, Handle> {
        self.handles.clone()
    }

    /// The log public key, lowercase hex.
    pub fn log_pubkey_hex(&self) -> String {
        self.keys
            .probe(Handle::LogSigner)
            .map(Probe::pubkey_hex)
            .unwrap_or_default()
    }

    pub(crate) fn id(&self, h: Handle) -> String {
        self.ids.get(&h).cloned().unwrap_or_default()
    }

    pub(crate) fn push<S: LedgerStore>(
        &mut self,
        store: &mut S,
        sum: &mut RunSummary,
        label: &str,
        payload: &str,
        tenant: Tenant,
    ) -> Result<(), LedgerError> {
        let rec = encode_record(payload, Some(label)).map_err(err("record too large"))?;
        store.append(&rec)?;
        self.log.append(&rec);
        sum.records += 1;
        *sum.by_tenant
            .entry(tenant.as_str().to_string())
            .or_insert(0) += 1;
        *sum.by_kind.entry(label.to_string()).or_insert(0) += 1;
        Ok(())
    }

    pub(crate) fn event<S: LedgerStore>(
        &mut self,
        store: &mut S,
        sum: &mut RunSummary,
        signer: Handle,
        f: EventFields,
    ) -> Result<(), LedgerError> {
        let probe = self
            .keys
            .probe(signer)
            .ok_or_else(|| LedgerError::Sign("missing demo key".into()))?;
        let payload = encode_event(&sign_event(probe, &f)?)?;
        self.last_ts = self.last_ts.max(f.ts);
        self.push(store, sum, f.kind.as_str(), &payload, f.tenant)
    }

    // Internal builder: the arguments are the event's own fields, so grouping them would only add a type.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn fields(
        &self,
        kind: Kind,
        tenant: Tenant,
        handle: Handle,
        ts: u64,
        subj: &str,
        label: LabelCode,
        decision: Decision,
        reason: ReasonCode,
        agent: Option<AgentMeta>,
    ) -> EventFields {
        EventFields {
            kind,
            tenant,
            key_id: self.id(handle),
            handle,
            ts,
            subject_hash: subj.to_string(),
            label,
            decision,
            reason,
            approval_ref: None,
            agent,
            role: None,
            attested_by: None,
            pubkey_fingerprint: None,
            evidence: None,
        }
    }

    pub(crate) fn approval<S: LedgerStore>(
        &mut self,
        store: &mut S,
        sum: &mut RunSummary,
        tenant: Tenant,
        signer: Handle,
        ev: ap::Event,
    ) -> Result<(), LedgerError> {
        let probe = self
            .keys
            .probe(signer)
            .ok_or_else(|| LedgerError::Sign("missing demo key".into()))?;
        let signed = ap::sign(probe, &ev).map_err(|e| LedgerError::Sign(e.to_string()))?;
        let payload = ap::encode(&signed).map_err(err("approval event"))?;
        let kind = match ev.body {
            Body::Request { .. } => "request",
            Body::Approve { .. } => "approve",
            Body::Deny { .. } => "deny",
            Body::Consume => "consume",
        };
        self.last_ts = self.last_ts.max(ev.ts);
        self.push(store, sum, &format!("approval.{kind}"), &payload, tenant)
    }

    /// Ask the real gate and the real Cedar engine, record the signed decision, return whether it allowed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decide<S: LedgerStore>(
        &mut self,
        store: &mut S,
        sum: &mut RunSummary,
        tenant: Tenant,
        principal: Handle,
        action: Action,
        subj: &str,
        now: u64,
    ) -> Result<bool, LedgerError> {
        let gate = match action {
            Action::Class(c) => {
                let state = ap::replay(&self.log, &self.directory, now);
                ap::check(
                    &state,
                    c,
                    subj,
                    now,
                    &AttestationPolicy {
                        accepted_for: vec![ActionClass::Direction],
                    },
                )
            }
            _ => GateDecision::Blocked(BlockReason::NoRequest),
        };
        let pid = self.id(principal);
        let role = self
            .directory
            .actors
            .get(&pid)
            .map_or(RoleName::Ai, |a| role_name(a.role));
        let req = Request {
            principal: pid,
            role,
            has_key: true,
            action,
            subject_hash: subj.to_string(),
            subject_kind: "synthetic".into(),
            now,
            env: Env::Dev,
        };
        let decision = self.engine.decide(&req, &gate, Mode::Enforce);
        let signer = self
            .keys
            .probe(Handle::Generator)
            .ok_or_else(|| LedgerError::Sign("missing demo key".into()))?;
        let rec = entropa_policy::sign_record(
            signer,
            &self.id(Handle::Generator),
            &req,
            &decision,
            &self.policy_hash,
            now,
        )
        .map_err(err("policy record"))?;
        self.last_ts = self.last_ts.max(now);
        self.push(store, sum, "policy.decision", &rec.payload, tenant)?;
        let allowed = decision.outcome == Outcome::Allow;
        if allowed {
            sum.allowed += 1;
        } else {
            sum.refused += 1;
        }
        Ok(allowed)
    }

    fn checkpoint<S: LedgerStore>(
        &mut self,
        store: &mut S,
        sum: &mut RunSummary,
        ts: u64,
    ) -> Result<(), LedgerError> {
        let log_probe = self
            .keys
            .probe(Handle::LogSigner)
            .ok_or_else(|| LedgerError::Sign("missing log key".into()))?;
        let cp = self.log.checkpoint(log_probe, ts);
        store.put_checkpoint(&cp)?;
        sum.checkpoints += 1;
        let proof: Vec<Hash> = if self.witnessed == 0 || self.witnessed == cp.size {
            Vec::new()
        } else {
            let leaves: Vec<Hash> = (0..cp.size)
                .map(|i| leaf_hash(&store.record(i).unwrap_or_default()))
                .collect();
            consistency_proof(&leaves, self.witnessed)
                .ok_or_else(|| LedgerError::Invalid("no consistency proof".into()))?
        };
        let body = json!({"v": 1, "log_id": log_id_for(&log_probe.pubkey_hex()),
            "checkpoint": serde_json::to_value(&cp).map_err(err("checkpoint"))?,
            "consistency": proof.iter().map(hex::encode).collect::<Vec<_>>()})
        .to_string();
        let statement = self
            .witness
            .cosign(&body, ts + 1)
            .map_err(|e| LedgerError::Verify(e.to_string()))?;
        store.put_witness(&statement)?;
        sum.witnesses += 1;
        self.witnessed = cp.size;
        self.last_ts = self.last_ts.max(ts + 1);
        Ok(())
    }

    fn register<S: LedgerStore>(
        &mut self,
        store: &mut S,
        sum: &mut RunSummary,
        ts: u64,
    ) -> Result<(), LedgerError> {
        let order = [
            Handle::HumanPrincipal,
            Handle::OrchestratorAgent,
            Handle::BuilderAgent,
            Handle::LogSigner,
            Handle::Generator,
            Handle::WitnessAzure,
            Handle::AgentEntropa,
            Handle::AgentBigironbank,
            Handle::AgentHippagrchealthcare,
        ];
        for h in order {
            let id = self.id(h);
            let role = self.directory.actors.get(&id).map(|a| role_code(a.role));
            let mut f = self.fields(
                Kind::DirectoryActor,
                Tenant::Entropa,
                h,
                ts,
                &hex::encode(
                    blake3::hash(format!("directory:{}", h.as_str()).as_bytes()).as_bytes(),
                ),
                LabelCode::ActorRegistered,
                Decision::Info,
                ReasonCode::None,
                None,
            );
            f.role = role;
            f.attested_by = if h == Handle::HumanPrincipal {
                Some(Handle::OrchestratorAgent)
            } else {
                None
            };
            f.pubkey_fingerprint = Some(id);
            self.event(store, sum, Handle::Generator, f)?;
        }
        self.registered = true;
        Ok(())
    }

    /// Run `scenarios` scripted scenarios starting at unix time `start_ts`: events, approvals,
    /// policy decisions, a signed checkpoint and a witness statement per batch.
    pub fn run(
        &mut self,
        store: &mut impl LedgerStore,
        scenarios: usize,
        start_ts: u64,
    ) -> Result<RunSummary, LedgerError> {
        if scenarios > MAX_SCENARIOS {
            return Err(LedgerError::Limit("too many scenarios in one run".into()));
        }
        if !self.registered && !store.is_empty() {
            return Err(LedgerError::Invalid(
                "a new generator cannot continue an existing ledger".into(),
            ));
        }
        let mut sum = RunSummary::default();
        let mut pending = false;
        if !self.registered {
            self.register(store, &mut sum, start_ts.max(self.last_ts))?;
            self.checkpoint(store, &mut sum, self.last_ts + 1)?;
        }
        for i in 0..scenarios {
            let t = (start_ts + 60 * (i as u64 + 1)).max(self.last_ts + 10);
            self.scenario(store, &mut sum, self.counter, t)?;
            self.counter += 1;
            pending = true;
            if (i + 1).is_multiple_of(5) {
                self.checkpoint(store, &mut sum, self.last_ts + 1)?;
                pending = false;
            }
        }
        if pending {
            self.checkpoint(store, &mut sum, self.last_ts + 1)?;
        }
        Ok(sum)
    }
}
