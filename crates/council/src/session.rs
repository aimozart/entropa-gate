//! The session state machine and quorum rule (the council design notes sections 4 and 5).

use crate::canon::hash_sorted;
use crate::{independent, required_role, CouncilError, Event, Provider, Role};
use std::collections::{BTreeMap, BTreeSet};

/// A session holds at most this many findings (the packet cap).
const MAX_FINDINGS: usize = 12;

/// Where a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Opened; the critic has not yet filed its report.
    CollectingFindings,
    /// The report is in; some finding still lacks a rebuttal.
    CollectingRebuttals,
    /// Every finding has a rebuttal; the packet is not yet compiled.
    PacketReady,
    /// The packet is compiled; items await the human's decisions.
    AwaitingDecision,
    /// Every item has a decision; the session is not yet closed.
    Decided,
    /// Closed by the scheduler.
    Closed,
    /// The expiry passed before the session closed; undecided items are pending and nothing changed.
    Expired,
}

/// The in-window decisions under review: `(subject_ref, provider that made the decision)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// One entry per decision in the window.
    pub decisions: Vec<(String, Provider)>,
}

/// The three things a session needs to be valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quorum {
    /// The critic's report is in.
    pub critic_report: bool,
    /// Every finding has a contestor rebuttal.
    pub rebuttals_complete: bool,
    /// The compiled packet carries a recommendation for every finding.
    pub recommendation_complete: bool,
}

impl Quorum {
    /// All three present.
    pub fn valid(&self) -> bool {
        self.critic_report && self.rebuttals_complete && self.recommendation_complete
    }
}

/// A change the human approved: the only thing that may ever reach production from a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedChange {
    /// The finding the change answers.
    pub finding_id: String,
    /// `test`, `cedar_change` or `lesson`.
    pub change_kind: String,
    /// The approvals-gate record that authorises it.
    pub approval_ref: String,
}

/// `BLAKE3("entropa-council-window-v1" 0x00 || for each ref in sorted order: u32be(len) || ref)`, hex.
pub fn window_hash(subject_refs: &[String]) -> String {
    hash_sorted(b"entropa-council-window-v1", subject_refs)
}

/// `BLAKE3("entropa-council-findings-v1" 0x00 || for each id in sorted order: u32be(len) || id)`, hex.
pub fn findings_hash(finding_ids: &[String]) -> String {
    hash_sorted(b"entropa-council-findings-v1", finding_ids)
}

#[derive(Debug)]
struct FindingRec {
    severity: String,
    critic: Provider,
}

#[derive(Debug)]
struct DecisionRec {
    accepted: bool,
    rejected: bool,
    change_kind: String,
    approval_ref: Option<String>,
}

/// One council session.
#[derive(Debug)]
pub struct Session {
    id: String,
    expires: u64,
    scope: BTreeMap<String, Provider>,
    findings: BTreeMap<String, FindingRec>,
    report: Option<(u64, String)>,
    rebutted: BTreeSet<String>,
    packet: Option<BTreeSet<String>>,
    decisions: BTreeMap<String, DecisionRec>,
    closed: Option<bool>,
    carried: Vec<String>,
}

fn bad(what: &str) -> CouncilError {
    CouncilError::Invalid(what.to_string())
}

fn provider_of(e: &Event, key: &str) -> Result<Provider, CouncilError> {
    e.str_field(key)
        .and_then(Provider::parse)
        .ok_or_else(|| bad("provider"))
}

impl Session {
    /// Open a session from a `session.opened` event signed by `signer`; the window hash must match `scope`.
    pub fn open(ev: &Event, signer: Role, scope: &Scope) -> Result<Session, CouncilError> {
        if ev.event_type() != "session.opened" {
            return Err(bad("not a session.opened event"));
        }
        if signer != Role::Scheduler {
            return Err(CouncilError::WrongRole);
        }
        let refs: Vec<String> = scope.decisions.iter().map(|(r, _)| r.clone()).collect();
        if ev.str_field("window_hash") != Some(window_hash(&refs).as_str())
            || ev.u64_field("n_decisions") != Some(refs.len() as u64)
        {
            return Err(CouncilError::WindowMismatch);
        }
        Ok(Session {
            id: ev.session_id().unwrap_or_default().to_string(),
            expires: ev.u64_field("expires").unwrap_or(0),
            scope: scope.decisions.iter().cloned().collect(),
            findings: BTreeMap::new(),
            report: None,
            rebutted: BTreeSet::new(),
            packet: None,
            decisions: BTreeMap::new(),
            closed: None,
            carried: vec![],
        })
    }

    /// Apply one event signed by `signer` at time `now`.
    pub fn apply(&mut self, ev: &Event, signer: Role, now: u64) -> Result<(), CouncilError> {
        let ty = ev.event_type();
        if required_role(ty) != Some(signer) {
            return Err(CouncilError::WrongRole);
        }
        match ev.session_id() {
            None => return Err(bad("not a session event")),
            Some(id) if id != self.id => return Err(CouncilError::WrongSession),
            Some(_) => {}
        }
        if self.closed.is_some() {
            return Err(CouncilError::OutOfOrder);
        }
        let terminal = matches!(ty, "session.closed" | "session.expired");
        if now >= self.expires && !terminal {
            return Err(CouncilError::Expired);
        }
        match ty {
            "finding.submitted" => self.finding(ev),
            "report.submitted" => self.report(ev),
            "rebuttal.submitted" => self.rebuttal(ev),
            "packet.compiled" => self.packet(ev),
            "decision.recorded" => self.decision(ev),
            "carryover.recorded" => self.carryover(ev),
            "change.linked" => self.change(ev),
            "proof.recorded" => self.known_item(ev),
            "session.closed" | "session.expired" => self.close(ev, now),
            _ => Err(CouncilError::OutOfOrder),
        }
    }

    fn known_item(&self, ev: &Event) -> Result<(), CouncilError> {
        match ev.str_field("finding_id") {
            Some(f) if self.findings.contains_key(f) => Ok(()),
            _ => Err(CouncilError::Incomplete),
        }
    }

    fn finding(&mut self, ev: &Event) -> Result<(), CouncilError> {
        if self.report.is_some() {
            return Err(CouncilError::OutOfOrder);
        }
        let id = ev.str_field("finding_id").unwrap_or_default().to_string();
        if self.findings.contains_key(&id) {
            return Err(CouncilError::Duplicate);
        }
        if self.findings.len() >= MAX_FINDINGS {
            return Err(CouncilError::Limit(
                "a session holds at most 12 findings".into(),
            ));
        }
        let subject = self
            .scope
            .get(ev.str_field("subject_ref").unwrap_or_default())
            .copied()
            .ok_or_else(|| bad("the subject is not in the window"))?;
        let critic = provider_of(ev, "provider")?;
        if !independent(critic.family(), subject.family()) {
            return Err(CouncilError::Independence);
        }
        let severity = ev.str_field("severity").unwrap_or_default().to_string();
        self.findings.insert(id, FindingRec { severity, critic });
        Ok(())
    }

    fn ids(&self) -> Vec<String> {
        self.findings.keys().cloned().collect()
    }

    fn report(&mut self, ev: &Event) -> Result<(), CouncilError> {
        if self.report.is_some() {
            return Err(CouncilError::Duplicate);
        }
        let n = ev.u64_field("n_findings").unwrap_or(u64::MAX);
        if n > MAX_FINDINGS as u64 {
            return Err(CouncilError::Limit(
                "a report covers at most 12 findings".into(),
            ));
        }
        let hash = ev.str_field("findings_hash").unwrap_or_default();
        if n != self.findings.len() as u64 || hash != findings_hash(&self.ids()) {
            return Err(CouncilError::Incomplete);
        }
        self.report = Some((n, hash.to_string()));
        Ok(())
    }

    fn rebuttal(&mut self, ev: &Event) -> Result<(), CouncilError> {
        if self.report.is_none() || self.packet.is_some() {
            return Err(CouncilError::OutOfOrder);
        }
        let id = ev.str_field("finding_id").unwrap_or_default();
        let critic = self
            .findings
            .get(id)
            .map(|f| f.critic)
            .ok_or(CouncilError::Incomplete)?;
        if self.rebutted.contains(id) {
            return Err(CouncilError::Duplicate);
        }
        if !independent(provider_of(ev, "provider")?.family(), critic.family()) {
            return Err(CouncilError::Independence);
        }
        self.rebutted.insert(id.to_string());
        Ok(())
    }

    fn rebuttals_complete(&self) -> bool {
        self.report.is_some() && self.findings.keys().all(|k| self.rebutted.contains(k))
    }

    fn packet(&mut self, ev: &Event) -> Result<(), CouncilError> {
        if self.packet.is_some() || !self.rebuttals_complete() {
            return Err(CouncilError::OutOfOrder);
        }
        let report_hash = self
            .report
            .as_ref()
            .map(|r| r.1.as_str())
            .unwrap_or_default();
        if ev.str_field("findings_hash") != Some(report_hash) {
            return Err(CouncilError::Incomplete);
        }
        let mut items: Vec<String> = ev
            .array_field("items")
            .iter()
            .filter_map(|i| {
                i.get("finding_id")
                    .and_then(|f| f.as_str())
                    .map(str::to_string)
            })
            .collect();
        items.sort();
        if items != self.ids() {
            return Err(CouncilError::Incomplete);
        }
        self.packet = Some(items.into_iter().collect());
        Ok(())
    }

    fn decision(&mut self, ev: &Event) -> Result<(), CouncilError> {
        let packet = self.packet.as_ref().ok_or(CouncilError::OutOfOrder)?;
        let id = ev.str_field("finding_id").unwrap_or_default().to_string();
        if !packet.contains(&id) {
            return Err(CouncilError::Incomplete);
        }
        if self.decisions.contains_key(&id) {
            return Err(CouncilError::Duplicate);
        }
        let hard = self
            .findings
            .get(&id)
            .is_some_and(|f| f.severity == "hard_rule");
        let attested = ev.bool_field("attested").unwrap_or(true);
        let has_auth = ev.str_field("auth_ref").is_some();
        if hard && (attested || !has_auth) {
            return Err(CouncilError::AttestationNotAccepted);
        }
        let decision = ev.str_field("decision").unwrap_or_default();
        let change = ev.str_field("change_kind").unwrap_or("none").to_string();
        let approval = ev.str_field("approval_ref").map(str::to_string);
        if decision == "accept" {
            if change != "none" && approval.is_none() {
                return Err(CouncilError::MissingApproval);
            }
        } else if change != "none" {
            return Err(bad("only an accepted item can carry a change"));
        }
        self.decisions.insert(
            id,
            DecisionRec {
                accepted: decision == "accept",
                rejected: decision == "reject",
                change_kind: change,
                approval_ref: approval,
            },
        );
        Ok(())
    }

    fn carryover(&mut self, ev: &Event) -> Result<(), CouncilError> {
        if self.report.is_none() || !self.carried.is_empty() {
            return Err(CouncilError::OutOfOrder);
        }
        let ids: Vec<String> = ev
            .array_field("carried_ids")
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
        if ids.is_empty() || ev.str_field("carried_hash") != Some(findings_hash(&ids).as_str()) {
            return Err(CouncilError::Incomplete);
        }
        if ids.iter().any(|i| self.findings.contains_key(i)) {
            return Err(CouncilError::Duplicate);
        }
        self.carried = ids;
        Ok(())
    }

    fn change(&self, ev: &Event) -> Result<(), CouncilError> {
        let id = ev.str_field("finding_id").unwrap_or_default();
        match self.decisions.get(id) {
            Some(d)
                if d.accepted && Some(d.change_kind.as_str()) == ev.str_field("change_kind") =>
            {
                Ok(())
            }
            _ => Err(bad("no accepted decision with this change")),
        }
    }

    fn counts(&self) -> (u64, u64, u64, u64) {
        let (mut a, mut r, mut d) = (0, 0, 0);
        for x in self.decisions.values() {
            if x.accepted {
                a += 1;
            } else if x.rejected {
                r += 1;
            } else {
                d += 1;
            }
        }
        (a, r, d, self.pending_items().len() as u64)
    }

    fn close(&mut self, ev: &Event, now: u64) -> Result<(), CouncilError> {
        let expired = ev.event_type() == "session.expired";
        let closing = ev.str_field("closing").unwrap_or_default();
        if expired != (closing != "all_decided") {
            return Err(bad("the closing code does not fit the event type"));
        }
        if expired && now < self.expires {
            return Err(CouncilError::OutOfOrder);
        }
        let want = (
            ev.u64_field("accepted"),
            ev.u64_field("rejected"),
            ev.u64_field("deferred"),
            ev.u64_field("pending"),
        );
        let (a, r, d, p) = self.counts();
        if want != (Some(a), Some(r), Some(d), Some(p)) {
            return Err(CouncilError::Incomplete);
        }
        let ok = match closing {
            "all_decided" => p == 0,
            "no_quorum" => !self.quorum().valid(),
            _ => p > 0 && self.quorum().valid(),
        };
        if !ok {
            return Err(CouncilError::Incomplete);
        }
        self.closed = Some(!expired);
        Ok(())
    }

    /// The state at time `now`.
    pub fn state(&self, now: u64) -> SessionState {
        match self.closed {
            Some(true) => return SessionState::Closed,
            Some(false) => return SessionState::Expired,
            None => {}
        }
        if now >= self.expires {
            return SessionState::Expired;
        }
        if self.report.is_none() {
            SessionState::CollectingFindings
        } else if !self.rebuttals_complete() {
            SessionState::CollectingRebuttals
        } else if self.packet.is_none() {
            SessionState::PacketReady
        } else if self.pending_items().is_empty() {
            SessionState::Decided
        } else {
            SessionState::AwaitingDecision
        }
    }

    /// The quorum so far.
    pub fn quorum(&self) -> Quorum {
        Quorum {
            critic_report: self.report.is_some(),
            rebuttals_complete: self.rebuttals_complete(),
            recommendation_complete: self.packet.is_some(),
        }
    }

    /// Findings the human has not yet decided (sorted).
    pub fn pending_items(&self) -> Vec<String> {
        self.packet.as_ref().map_or_else(Vec::new, |p| {
            p.iter()
                .filter(|i| !self.decisions.contains_key(*i))
                .cloned()
                .collect()
        })
    }

    /// Changes approved by a recorded human decision in a valid session; empty without quorum.
    pub fn approved_changes(&self) -> Vec<ApprovedChange> {
        if !self.quorum().valid() {
            return vec![];
        }
        self.decisions
            .iter()
            .filter(|(_, d)| d.accepted && d.change_kind != "none")
            .filter_map(|(id, d)| {
                Some(ApprovedChange {
                    finding_id: id.clone(),
                    change_kind: d.change_kind.clone(),
                    approval_ref: d.approval_ref.clone()?,
                })
            })
            .collect()
    }

    /// Findings carried over to the next session, in the recorded (stable) order.
    pub fn carried(&self) -> Vec<String> {
        self.carried.clone()
    }
}
