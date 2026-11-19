//! The retrieval evaluation harness and the planted-suite generator (the decision-memory design notes section 7). All data
//! is synthetic; the generator is a pure function of its seed (a splitmix64 stream, no clock, no entropy).

use crate::memory::{LexicalIndex, Precedent};
use crate::CouncilError;

const TENANTS: [&str; 3] = ["entropa", "bigironbank", "hippagrchealthcare"];
const CHANGES: [&str; 3] = ["test", "cedar_change", "lesson"];
const SEVERITIES: [&str; 4] = ["low", "medium", "high", "hard_rule"];
const N_CLASSES: usize = 24;
const N_REASONS: usize = 6;
/// Smallest and largest suite: enough revoked precedents for five poison cases, and room for unique triples.
const MIN_N: usize = 60;
const MAX_N: usize = 600;

/// One planted retrieval case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalCase {
    /// Case id.
    pub id: String,
    /// The tenant asking.
    pub tenant: String,
    /// The query terms.
    pub query: Vec<String>,
    /// `Some(ids)`: any of these in the top k is a hit; `Some(empty)`: nothing may be returned (abstention);
    /// `None`: no expectation, only the forbidden ids matter.
    pub expected: Option<Vec<String>>,
    /// Ids that must never be returned (revoked, unaccepted, another tenant's).
    pub forbidden: Vec<String>,
}

/// The measured numbers of a retrieval evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalReport {
    /// Cases expecting a hit that got one in the top k, per mille (None if there are none).
    pub recall_permille: Option<u32>,
    /// Mean of `floor(1000 / rank)` over those cases (0 for a miss), floored (None if there are none).
    pub mrr_permille: Option<u32>,
    /// Cases expecting abstention that returned nothing, per mille (None if there are none).
    pub abstention_permille: Option<u32>,
    /// Forbidden ids returned, summed over all cases.
    pub violations: u64,
}

/// Acceptance thresholds (decision D7 of the memory design).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalThresholds {
    /// Minimum recall (default 900).
    pub recall_min: u32,
    /// Minimum abstention (default 950).
    pub abstention_min: u32,
    /// Maximum violations (default 0).
    pub violations_max: u64,
}

impl Default for RetrievalThresholds {
    fn default() -> Self {
        RetrievalThresholds {
            recall_min: 900,
            abstention_min: 950,
            violations_max: 0,
        }
    }
}

impl RetrievalReport {
    /// `Ok` if every threshold is met, else the failing metric names (`recall`, `abstention`, `violations`); a metric
    /// that was not measured fails.
    pub fn meets(&self, t: &RetrievalThresholds) -> Result<(), Vec<String>> {
        let mut failed = Vec::new();
        if self.recall_permille.is_none_or(|v| v < t.recall_min) {
            failed.push("recall".to_string());
        }
        if self
            .abstention_permille
            .is_none_or(|v| v < t.abstention_min)
        {
            failed.push("abstention".to_string());
        }
        if self.violations > t.violations_max {
            failed.push("violations".to_string());
        }
        if failed.is_empty() {
            Ok(())
        } else {
            Err(failed)
        }
    }
}

/// Run `cases` against `index` at `k` and score them.
pub fn evaluate_retrieval(
    index: &LexicalIndex,
    cases: &[RetrievalCase],
    k: usize,
) -> Result<RetrievalReport, CouncilError> {
    let (mut want_hit, mut hit, mut rr_sum) = (0u64, 0u64, 0u64);
    let (mut want_none, mut none_ok, mut violations) = (0u64, 0u64, 0u64);
    for c in cases {
        let ids: Vec<String> = index
            .search(&c.tenant, &c.query, k)?
            .into_iter()
            .map(|h| h.id)
            .collect();
        violations += ids.iter().filter(|i| c.forbidden.contains(i)).count() as u64;
        match &c.expected {
            Some(e) if e.is_empty() => {
                want_none += 1;
                none_ok += u64::from(ids.is_empty());
            }
            Some(e) => {
                want_hit += 1;
                if let Some(pos) = ids.iter().position(|i| e.contains(i)) {
                    hit += 1;
                    rr_sum += 1000 / (pos as u64 + 1);
                }
            }
            None => {}
        }
    }
    let per_mille =
        |num: u64, den: u64| (den > 0).then(|| u32::try_from(1000 * num / den).unwrap_or(1000));
    Ok(RetrievalReport {
        recall_permille: per_mille(hit, want_hit),
        mrr_permille: (want_hit > 0).then(|| u32::try_from(rr_sum / want_hit).unwrap_or(1000)),
        abstention_permille: per_mille(none_ok, want_none),
        violations,
    })
}

/// A deterministic synthetic suite: precedents (including revoked ones) and planted cases of every kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlantedSuite {
    /// All precedents, revoked ones included.
    pub precedents: Vec<Precedent>,
    /// The ids revoked in this suite.
    pub revoked: Vec<String>,
    /// Exact-match, near-match, no-match, poisoned and cross-tenant cases.
    pub cases: Vec<RetrievalCase>,
}

/// splitmix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The four varying codes of a precedent: class, change, severity, reason (indexes into the vocabularies).
type Codes = [usize; 4];

fn terms_of(c: Codes) -> Vec<String> {
    let mut v = vec![
        format!("change={}", CHANGES[c[1]]),
        format!("class=class_{:02}", c[0]),
        "decision=accept".to_string(),
        format!("reason=reason_{}", c[3]),
        format!("severity={}", SEVERITIES[c[2]]),
    ];
    v.sort();
    v
}

/// Generate a planted suite from a seed: `n` admitted precedents plus `n / 20` revoked ones, over three tenants. Within a
/// tenant no two precedents share their (class, change, severity) triple, so an exact query has exactly one best match.
pub fn planted_retrieval_suite(seed: u64, n: usize) -> Result<PlantedSuite, CouncilError> {
    if !(MIN_N..=MAX_N).contains(&n) {
        return Err(CouncilError::Limit("n is 60 to 600".into()));
    }
    let mut rng = Rng(seed);
    let total = n + n / 20;
    let mut triples: Vec<Vec<(usize, usize, usize)>> = Vec::new();
    for _ in TENANTS {
        let mut all: Vec<(usize, usize, usize)> = (0..N_CLASSES)
            .flat_map(|c| {
                (0..CHANGES.len()).flat_map(move |h| (0..SEVERITIES.len()).map(move |s| (c, h, s)))
            })
            .collect();
        for i in (1..all.len()).rev() {
            all.swap(i, rng.below(i + 1));
        }
        triples.push(all);
    }
    let mut codes: Vec<Codes> = Vec::new();
    let mut precedents = Vec::new();
    for i in 0..total {
        let t = i % TENANTS.len();
        let (c, h, s) = triples[t].pop().unwrap_or((0, 0, 0));
        let code = [c, h, s, rng.below(N_REASONS)];
        precedents.push(Precedent {
            id: format!("p{i:04}"),
            tenant: TENANTS[t].to_string(),
            terms: terms_of(code),
        });
        codes.push(code);
    }
    let revoked: Vec<String> = precedents[n..].iter().map(|p| p.id.clone()).collect();
    let near = |code: Codes, rng: &mut Rng| {
        let mut q = code;
        q[3] = (code[3] + 1 + rng.below(N_REASONS - 1)) % N_REASONS;
        terms_of(q)
    };
    let mut cases = Vec::new();
    let case = |id: String,
                tenant: &str,
                query: Vec<String>,
                expected: Option<Vec<String>>,
                forbidden: Vec<String>| {
        RetrievalCase {
            id,
            tenant: tenant.to_string(),
            query,
            expected,
            forbidden,
        }
    };
    for j in 0..20 {
        let a = rng.below(n);
        let p = &precedents[a];
        cases.push(case(
            format!("exact-{j:02}"),
            &p.tenant,
            terms_of(codes[a]),
            Some(vec![p.id.clone()]),
            vec![],
        ));
    }
    for j in 0..10 {
        let a = rng.below(n);
        let p = &precedents[a];
        cases.push(case(
            format!("near-{j:02}"),
            &p.tenant,
            near(codes[a], &mut rng),
            Some(vec![p.id.clone()]),
            vec![],
        ));
    }
    for j in 0..20 {
        let query = vec![
            format!("class=novel-{j}"),
            "decision=accept".to_string(),
            format!("reason=reason_{}", rng.below(N_REASONS)),
        ];
        cases.push(case(
            format!("none-{j:02}"),
            TENANTS[j % TENANTS.len()],
            query,
            Some(vec![]),
            vec![],
        ));
    }
    for (j, r) in (n..total).enumerate() {
        let p = &precedents[r];
        cases.push(case(
            format!("poison-{j:03}a"),
            &p.tenant,
            terms_of(codes[r]),
            None,
            vec![p.id.clone()],
        ));
        cases.push(case(
            format!("poison-{j:03}b"),
            &p.tenant,
            near(codes[r], &mut rng),
            None,
            vec![p.id.clone()],
        ));
    }
    for j in 0..10 {
        let a = rng.below(n);
        let p = &precedents[a];
        let other = TENANTS
            .iter()
            .filter(|t| **t != p.tenant)
            .nth(rng.below(2))
            .copied()
            .unwrap_or(TENANTS[0]);
        cases.push(case(
            format!("xtenant-{j:02}"),
            other,
            terms_of(codes[a]),
            None,
            vec![p.id.clone()],
        ));
    }
    Ok(PlantedSuite {
        precedents,
        revoked,
        cases,
    })
}
