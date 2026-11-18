//! Surplus findings carry over to the next weekly session in a stable order.

use crate::event::is_token;
use crate::CouncilError;
use std::collections::BTreeSet;

/// A candidate finding for a session: its id and severity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Finding id.
    pub id: String,
    /// `low`, `medium`, `high` or `hard_rule`.
    pub severity: String,
}

/// The split of candidates into this session and the next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carryover {
    /// The ids that fit the cap, in stable order.
    pub in_session: Vec<String>,
    /// The surplus ids, in stable order.
    pub carried: Vec<String>,
}

fn rank(severity: &str) -> Option<u8> {
    match severity {
        "hard_rule" => Some(0),
        "high" => Some(1),
        "medium" => Some(2),
        "low" => Some(3),
        _ => None,
    }
}

/// Split `candidates` at `cap`: stable order is severity (hard_rule, high, medium, low) then id; independent of the
/// order of the input. Refused: a zero cap, an id that is not a token, a duplicate id, an unknown severity.
pub fn plan_carryover(candidates: &[Candidate], cap: usize) -> Result<Carryover, CouncilError> {
    if cap == 0 {
        return Err(CouncilError::Invalid("the cap must be at least 1".into()));
    }
    let mut seen = BTreeSet::new();
    let mut keyed: Vec<(u8, &str)> = Vec::with_capacity(candidates.len());
    for c in candidates {
        let r =
            rank(&c.severity).ok_or_else(|| CouncilError::Invalid("unknown severity".into()))?;
        if !is_token(&c.id) || !seen.insert(c.id.as_str()) {
            return Err(CouncilError::Invalid(
                "a candidate id is malformed or repeated".into(),
            ));
        }
        keyed.push((r, c.id.as_str()));
    }
    keyed.sort_unstable();
    let ids: Vec<String> = keyed.into_iter().map(|(_, id)| id.to_string()).collect();
    let split = cap.min(ids.len());
    Ok(Carryover {
        in_session: ids[..split].to_vec(),
        carried: ids[split..].to_vec(),
    })
}
