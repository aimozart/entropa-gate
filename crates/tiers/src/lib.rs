//! `entropa-tiers` (AT2): who may do what, decided by code and recorded once per decision. The order of one decision is fixed (a stage record (not published)): verify the token and
//! the revocation list, map the request to a closed action, the token's own limits, the tier policy (Cedar behind a trait), the egress guard for outbound actions, the
//! retrieval guard for corpus reads, then the record, then the result. Every step may only deny. The clock is passed in; nothing here reads a clock, a network or a key.

pub mod adapters;
pub mod append;
pub mod cedar;
pub mod change;

use entropa_tokens::{Deny, Tier, Verified};

/// The closed list of actions. Anything else is unknown and denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read the sealed corpus (answers cite clauses or abstain).
    ReadCorpus,
    /// Send a request to a model (outbound: the egress guard applies).
    CallModel,
    /// Call a listed tool (outbound: the egress guard applies).
    CallTool,
}

impl Action {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::ReadCorpus => "read_corpus",
            Action::CallModel => "call_model",
            Action::CallTool => "call_tool",
        }
    }
    /// Parse the wire name; `None` for anything outside the closed list.
    pub fn parse(s: &str) -> Option<Action> {
        match s {
            "read_corpus" => Some(Action::ReadCorpus),
            "call_model" => Some(Action::CallModel),
            "call_tool" => Some(Action::CallTool),
            _ => None,
        }
    }
}

/// Why a request was denied (closed). Token refusals keep the token verifier's own code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyCode {
    /// The token verifier refused it.
    Token(Deny),
    /// The action is not on the closed list.
    UnknownAction,
    /// The tier may never do this (T0 egress or tool, T1 tool).
    TierForbids,
    /// The corpus hash is not in the token.
    CorpusNotInToken,
    /// The action (or tool) is not in the token.
    ActionNotInToken,
    /// The cost is over the token's spend cap.
    SpendCap,
    /// The calls in the last minute reach the token's rate cap.
    RateCap,
    /// The tier policy says no.
    PolicyDenied,
    /// The policy engine failed (fail closed).
    PolicyError,
    /// The egress guard blocked the payload.
    EgressBlocked,
    /// The egress guard failed (fail closed).
    EgressError,
    /// The retrieval guard failed (fail closed).
    RetrievalError,
    /// The record could not be written (fail closed: no result is returned).
    RecordFailed,
    /// A step panicked after the reservation (fail closed; the reservation is given back).
    InternalError,
}

impl DenyCode {
    /// The closed word written to the trail.
    pub fn as_str(self) -> &'static str {
        match self {
            DenyCode::Token(d) => d.as_str(),
            DenyCode::UnknownAction => "unknown_action",
            DenyCode::TierForbids => "tier_forbids",
            DenyCode::CorpusNotInToken => "corpus_not_in_token",
            DenyCode::ActionNotInToken => "action_not_in_token",
            DenyCode::SpendCap => "spend_cap",
            DenyCode::RateCap => "rate_cap",
            DenyCode::PolicyDenied => "policy_denied",
            DenyCode::PolicyError => "policy_error",
            DenyCode::EgressBlocked => "egress_blocked",
            DenyCode::EgressError => "egress_error",
            DenyCode::RetrievalError => "retrieval_error",
            DenyCode::RecordFailed => "record_failed",
            DenyCode::InternalError => "internal_error",
        }
    }
}

/// The decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allowed.
    Allowed,
    /// Denied, with the closed reason.
    Denied(DenyCode),
}

/// One request. The text is carried for the collaborators and is NEVER an input to steps 1 to 4 (A3).
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// The design-A token bytes.
    pub token: Vec<u8>,
    /// The parent token bytes, when the token names one.
    pub parent: Option<Vec<u8>>,
    /// The action word as sent.
    pub action: String,
    /// The corpus hash (64 hex) for a corpus read.
    pub corpus: Option<String>,
    /// The tool name for a tool call.
    pub tool: Option<String>,
    /// The cost of this call in micro-USD.
    pub cost: u64,
    /// The outbound payload (what would leave), for the egress guard.
    pub payload: Vec<u8>,
    /// Free text (the user's words): never a decision input.
    pub text: String,
}

/// The one record of a decision: closed codes and hashes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierRecord {
    /// `token_used` for an allowed request, `token_denied` for a denied one.
    pub label: &'static str,
    /// `allowed` or `denied`.
    pub decision: &'static str,
    /// `allowed` or the closed denial word.
    pub reason: String,
    /// The tier of the verified token, when there was one.
    pub tier: Option<&'static str>,
    /// The closed action word, or `unknown`.
    pub action: &'static str,
    /// Hash of the token id (never the id or the token), when the token verified.
    pub token_hash: Option<String>,
    /// Hash of the whole request.
    pub request_hash: String,
    /// The policy version hash.
    pub policy_hash: String,
    /// The clock that was passed in.
    pub ts: u64,
}

/// What `decide` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The decision.
    pub decision: Decision,
    /// The record that was written for it (also written to the sink).
    pub record: TierRecord,
    /// The answer of the retrieval guard or the tool, for an allowed request only.
    pub answer: Option<Vec<u8>>,
}

/// The egress guard's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Guard {
    /// Nothing leaves that should not.
    Allow,
    /// The guard blocks the payload.
    Block,
}

/// Verifies a token offline.
pub trait TokenVerifier {
    /// Verify the token (and its parent) at `now`.
    fn verify(&self, token: &[u8], parent: Option<&[u8]>, now: u64) -> Result<Verified, Deny>;
}
/// The tier policy (Cedar behind this trait): default deny.
pub trait PolicyEngine {
    /// `Ok(true)` allows; `Ok(false)` denies; `Err` is an engine failure (denied).
    fn allows(&self, tier: Tier, action: Action, tool: Option<&str>) -> Result<bool, String>;
    /// The hash of the policy in force (written in every record).
    fn policy_hash(&self) -> String;
}
/// The egress guard.
pub trait EgressGuard {
    /// Check an outbound payload at a tier. `Err` is a guard failure (denied).
    fn check(&self, tier: Tier, payload: &[u8]) -> Result<Guard, String>;
}
/// The retrieval guard: read a sealed corpus, never outside the allowed set.
pub trait Retrieval {
    /// Read `corpus` (a hash that the token names) for `query`.
    fn read(&self, corpus: &str, query: &str) -> Result<Vec<u8>, String>;
}
/// Spend and rate state per token.
pub trait Meter {
    /// Micro-USD spent so far by this token id.
    fn spent(&self, token_id: &str) -> u64;
    /// Calls by this token id in the minute before `now`.
    fn calls_last_minute(&self, token_id: &str, now: u64) -> u64;
    /// Check the caps and record the usage in ONE step (atomic in a meter that is shared). The default is the old read-only check and records nothing (AT2 fakes).
    fn try_reserve(
        &self,
        token_id: &str,
        cost: u64,
        spend_cap: u64,
        rate_cap: u64,
        now: u64,
    ) -> Result<(), MeterDeny> {
        if self.spent(token_id).saturating_add(cost) > spend_cap {
            return Err(MeterDeny::Spend);
        }
        if self.calls_last_minute(token_id, now) >= rate_cap {
            return Err(MeterDeny::Rate);
        }
        Ok(())
    }
    /// Give a reservation back (a later step denied). The default does nothing.
    fn release(&self, _token_id: &str, _cost: u64, _now: u64) {}
}

/// Which cap a reservation hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterDeny {
    /// The spend cap.
    Spend,
    /// The rate cap.
    Rate,
}
/// Where records go. An error means the record was NOT written.
pub trait RecordSink {
    /// Write one record.
    fn write(&self, record: &TierRecord) -> Result<(), String>;
}

/// The enforcement point.
pub struct Gate<'a> {
    /// Token verification.
    pub verifier: &'a dyn TokenVerifier,
    /// Tier policy.
    pub policy: &'a dyn PolicyEngine,
    /// Egress guard.
    pub egress: &'a dyn EgressGuard,
    /// Retrieval guard.
    pub retrieval: &'a dyn Retrieval,
    /// Spend and rate state.
    pub meter: &'a dyn Meter,
    /// Record sink.
    pub sink: &'a dyn RecordSink,
}

/// Hash of the whole request (length-prefixed fields, so no two requests share an encoding). Only the hash is ever recorded.
fn request_hash(r: &Request) -> String {
    let mut h = blake3::Hasher::new();
    let mut put = |b: &[u8]| {
        h.update(&(b.len() as u64).to_be_bytes());
        h.update(b);
    };
    put(&r.token);
    put(r.parent.as_deref().unwrap_or(&[]));
    put(r.action.as_bytes());
    put(r.corpus.as_deref().unwrap_or("").as_bytes());
    put(r.tool.as_deref().unwrap_or("").as_bytes());
    put(&r.cost.to_be_bytes());
    put(&r.payload);
    put(r.text.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

/// What the steps found before the record is written.
struct Verdict {
    decision: Decision,
    tier: Option<&'static str>,
    action: &'static str,
    token_hash: Option<String>,
    answer: Option<Vec<u8>>,
}

impl Gate<'_> {
    /// Decide one request at time `now`. Exactly one record is written before this returns. Steps, in order (each may only deny): token, closed action, tier ceiling,
    /// the token's own limits, the tier policy, the egress guard (outbound actions), the retrieval guard (corpus reads), the record. The request text is not read by any of them.
    pub fn decide(&self, req: &Request, now: u64) -> Outcome {
        let reserved: std::cell::Cell<Option<(String, u64)>> = std::cell::Cell::new(None);
        let stepped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.steps(req, now, &reserved)
        }));
        let v = stepped.unwrap_or_else(|_| Verdict {
            decision: Decision::Denied(DenyCode::InternalError),
            tier: None,
            action: Action::parse(&req.action).map_or("unknown", Action::as_str),
            token_hash: None,
            answer: None,
        });
        let held = reserved.take();
        // a reservation survives only an allowed decision that is then recorded
        let release = |this: &Self| {
            if let Some((id, cost)) = &held {
                this.meter.release(id, *cost, now);
            }
        };
        if matches!(v.decision, Decision::Denied(_)) {
            release(self);
        }
        let (label, decision_word, reason) = match v.decision {
            Decision::Allowed => ("token_used", "allowed", "allowed".to_string()),
            Decision::Denied(c) => ("token_denied", "denied", c.as_str().to_string()),
        };
        let mut record = TierRecord {
            label,
            decision: decision_word,
            reason,
            tier: v.tier,
            action: v.action,
            token_hash: v.token_hash,
            request_hash: request_hash(req),
            policy_hash: self.policy.policy_hash(),
            ts: now,
        };
        match self.sink.write(&record) {
            Ok(()) => Outcome {
                decision: v.decision,
                record,
                answer: v.answer,
            },
            Err(_) => {
                if matches!(v.decision, Decision::Allowed) {
                    release(self);
                }
                // the record could not be written: nothing is returned except the denial (and the record that could not be stored says so)
                record.label = "token_denied";
                record.decision = "denied";
                record.reason = DenyCode::RecordFailed.as_str().to_string();
                Outcome {
                    decision: Decision::Denied(DenyCode::RecordFailed),
                    record,
                    answer: None,
                }
            }
        }
    }

    fn steps(
        &self,
        req: &Request,
        now: u64,
        reserved: &std::cell::Cell<Option<(String, u64)>>,
    ) -> Verdict {
        let action = Action::parse(&req.action);
        let action_word = action.map_or("unknown", Action::as_str);
        let deny = |c: DenyCode, tier: Option<&'static str>, token_hash: Option<String>| Verdict {
            decision: Decision::Denied(c),
            tier,
            action: action_word,
            token_hash,
            answer: None,
        };
        // 1. the token (and its parent), offline, at the clock passed in
        let ok = match self.verifier.verify(&req.token, req.parent.as_deref(), now) {
            Ok(v) => v,
            Err(d) => return deny(DenyCode::Token(d), None, None),
        };
        let claims = &ok.claims;
        let tier = Some(claims.tier.as_str());
        let th = Some(hex::encode(blake3::hash(ok.token_id.as_bytes()).as_bytes()));
        let d = |c: DenyCode| deny(c, tier, th.clone());
        // 2. the closed action
        let Some(action) = action else {
            return d(DenyCode::UnknownAction);
        };
        // 3. the tier ceiling, in code: T0 reads only; T1 reads and calls a model; T2 also calls tools; T3 change control is another stage
        let ceiling: &[Action] = match claims.tier {
            Tier::T0 => &[Action::ReadCorpus],
            Tier::T1 => &[Action::ReadCorpus, Action::CallModel],
            Tier::T2 => &[Action::ReadCorpus, Action::CallModel, Action::CallTool],
            Tier::T3 => &[],
        };
        if !ceiling.contains(&action) {
            return d(DenyCode::TierForbids);
        }
        // 4. the token's own limits
        if !claims.actions.iter().any(|a| a == action.as_str()) {
            return d(DenyCode::ActionNotInToken);
        }
        match action {
            Action::ReadCorpus => {
                if !req
                    .corpus
                    .as_ref()
                    .is_some_and(|c| claims.corpora.contains(c))
                {
                    return d(DenyCode::CorpusNotInToken);
                }
            }
            Action::CallTool => {
                if !req
                    .tool
                    .as_ref()
                    .is_some_and(|t| claims.actions.contains(t))
                {
                    return d(DenyCode::ActionNotInToken);
                }
            }
            Action::CallModel => {}
        }
        match self.meter.try_reserve(
            &ok.token_id,
            req.cost,
            claims.spend_cap,
            claims.rate_cap,
            now,
        ) {
            Ok(()) => reserved.set(Some((ok.token_id.clone(), req.cost))),
            Err(MeterDeny::Spend) => return d(DenyCode::SpendCap),
            Err(MeterDeny::Rate) => return d(DenyCode::RateCap),
        }
        // 5. the tier policy
        match self.policy.allows(claims.tier, action, req.tool.as_deref()) {
            Ok(true) => {}
            Ok(false) => return d(DenyCode::PolicyDenied),
            Err(_) => return d(DenyCode::PolicyError),
        }
        // 6. the egress guard, for what would leave
        if matches!(action, Action::CallModel | Action::CallTool) {
            match self.egress.check(claims.tier, &req.payload) {
                Ok(Guard::Allow) => {}
                Ok(Guard::Block) => return d(DenyCode::EgressBlocked),
                Err(_) => return d(DenyCode::EgressError),
            }
        }
        // 7. the retrieval guard, only for a corpus the token names
        let answer = if action == Action::ReadCorpus {
            let corpus = req.corpus.as_deref().unwrap_or_default();
            match self.retrieval.read(corpus, &req.text) {
                Ok(a) => Some(a),
                Err(_) => return d(DenyCode::RetrievalError),
            }
        } else {
            None
        };
        Verdict {
            decision: Decision::Allowed,
            tier,
            action: action.as_str(),
            token_hash: th,
            answer,
        }
    }
}

/// The real token verifier: `entropa_tokens::verify_a` with the node's audience, the stated limits and the revocation list in force. The clock is the caller's.
pub struct OfflineVerifier {
    /// The issuer keys trusted.
    pub trust: entropa_tokens::Trust,
    /// The audience this node is.
    pub audience: String,
    /// Seconds a not-yet-valid token is tolerated.
    pub skew: u64,
    /// Longest token lifetime accepted.
    pub max_ttl: u64,
    /// A revocation list older than this many seconds denies (300 in the plan).
    pub rev_max_age: u64,
    /// The signed revocation list in force, if any (none denies: fail closed).
    pub revocations: Option<Vec<u8>>,
}

impl TokenVerifier for OfflineVerifier {
    fn verify(&self, token: &[u8], parent: Option<&[u8]>, now: u64) -> Result<Verified, Deny> {
        let p = entropa_tokens::Policy {
            audience: self.audience.clone(),
            now,
            skew: self.skew,
            max_ttl: self.max_ttl,
            rev_max_age: self.rev_max_age,
        };
        entropa_tokens::verify_a(token, &self.trust, &p, self.revocations.as_deref(), parent)
    }
}
