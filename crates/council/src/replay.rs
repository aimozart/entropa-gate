//! The replay harness for the "prove" step: pure, deterministic, hash-checked.

use crate::CouncilError;
use std::collections::BTreeSet;

/// A replayed decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Allowed.
    Allow,
    /// Denied.
    Deny,
}

/// Anything that decides a recorded request under some policy set.
pub trait Decider {
    /// Decide the synthetic request object `input`.
    fn decide(&self, input: &str) -> Verdict;
}

/// One recorded request: its id, the content-addressed input, the hash recorded with it, and the outcome that
/// followed (`bad` if overridden or an incident).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayItem {
    /// Decision id.
    pub id: String,
    /// The synthetic request object.
    pub input: String,
    /// The hash recorded in the ledger for `input`.
    pub input_hash: String,
    /// True if the recorded outcome was `overridden_by_human` or `incident`.
    pub bad_outcome: bool,
}

/// The counts of a replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    /// Requests replayed.
    pub replayed: u64,
    /// Requests whose verdict changed.
    pub changed: u64,
    /// Changed from allow to deny.
    pub newly_denied: u64,
    /// Changed from deny to allow.
    pub newly_allowed: u64,
    /// Ids of the changed decisions, sorted.
    pub changed_ids: Vec<String>,
    /// Bad-outcome decisions the candidate denies.
    pub bad_denied: u64,
    /// Bad-outcome decisions the candidate still allows.
    pub bad_allowed: u64,
}

/// `BLAKE3("entropa-council-replay-input-v1" 0x00 || u32be(len) || input)`, hex.
pub fn input_hash(input: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-council-replay-input-v1\0");
    h.update(&(input.len() as u32).to_be_bytes());
    h.update(input.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

/// Replay `items` under `current` and `candidate`; every input must match its recorded hash.
pub fn replay(
    items: &[ReplayItem],
    current: &dyn Decider,
    candidate: &dyn Decider,
) -> Result<ReplayReport, CouncilError> {
    let mut seen = BTreeSet::new();
    for it in items {
        if !seen.insert(it.id.as_str()) {
            return Err(CouncilError::Invalid("two requests share an id".into()));
        }
    }
    for it in items {
        if input_hash(&it.input) != it.input_hash {
            return Err(CouncilError::HashMismatch(it.id.clone()));
        }
    }
    let mut r = ReplayReport {
        replayed: items.len() as u64,
        changed: 0,
        newly_denied: 0,
        newly_allowed: 0,
        changed_ids: vec![],
        bad_denied: 0,
        bad_allowed: 0,
    };
    for it in items {
        let (before, after) = (current.decide(&it.input), candidate.decide(&it.input));
        match (before, after) {
            (Verdict::Allow, Verdict::Deny) => r.newly_denied += 1,
            (Verdict::Deny, Verdict::Allow) => r.newly_allowed += 1,
            _ => {}
        }
        if before != after {
            r.changed += 1;
            r.changed_ids.push(it.id.clone());
        }
        if it.bad_outcome {
            match after {
                Verdict::Deny => r.bad_denied += 1,
                Verdict::Allow => r.bad_allowed += 1,
            }
        }
    }
    r.changed_ids.sort();
    Ok(r)
}
