//! Critic-reliability scoring from accepted and rejected findings (the council design notes section 8).

/// What the human decided about a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Accepted.
    Accepted,
    /// Rejected.
    Rejected,
    /// Deferred (ignored by the score).
    Deferred,
}

/// A reviewer's score for one finding class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Score {
    /// Severity-weighted accepted findings.
    pub accepted_weight: u64,
    /// Severity-weighted rejected findings.
    pub rejected_weight: u64,
    /// Number of decided (accepted or rejected) findings in the window.
    pub decided: u64,
    /// `floor(1000 * (accepted_weight + 1) / (accepted_weight + rejected_weight + 2))`.
    pub permille: u32,
}

struct Record {
    reviewer: String,
    class: String,
    weight: u64,
    verdict: Verdict,
    ts: u64,
}

/// Rolling reliability records.
pub struct Reliability {
    window_secs: u64,
    records: Vec<Record>,
}

fn weight(severity: &str) -> u64 {
    match severity {
        "medium" => 2,
        "high" => 3,
        "hard_rule" => 4,
        _ => 1,
    }
}

impl Reliability {
    /// A new, empty record with a rolling window of `window_secs`.
    pub fn new(window_secs: u64) -> Reliability {
        Reliability {
            window_secs,
            records: vec![],
        }
    }
    /// Record one decided finding (`severity`: low 1, medium 2, high 3, hard_rule 4).
    pub fn record(
        &mut self,
        reviewer: &str,
        class: &str,
        severity: &str,
        verdict: Verdict,
        ts: u64,
    ) {
        self.records.push(Record {
            reviewer: reviewer.into(),
            class: class.into(),
            weight: weight(severity),
            verdict,
            ts,
        });
    }
    /// The score of `reviewer` for `class` at time `now` (decisions older than the window are ignored).
    pub fn score(&self, reviewer: &str, class: &str, now: u64) -> Score {
        let (mut a, mut r, mut n) = (0u64, 0u64, 0u64);
        for x in self.records.iter().filter(|x| {
            x.reviewer == reviewer
                && x.class == class
                && now.saturating_sub(x.ts) < self.window_secs
        }) {
            match x.verdict {
                Verdict::Accepted => {
                    a += x.weight;
                    n += 1;
                }
                Verdict::Rejected => {
                    r += x.weight;
                    n += 1;
                }
                Verdict::Deferred => {}
            }
        }
        Score {
            accepted_weight: a,
            rejected_weight: r,
            decided: n,
            permille: (1000 * (a + 1) / (a + r + 2)) as u32,
        }
    }
}
