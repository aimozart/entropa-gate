//! Decision memory, stage S12d-c: the exact lexical index of the decision-memory design notes sections 3 and 4, with its
//! integer scorer, index hash, manifest hash and memory hash. The retrieval evaluation harness and the planted-suite
//! generator of section 7 live in `memory_eval`. No float, no clock, no file, no model.

use crate::canon::canonical;
use crate::event::{is_hex, is_token};
use crate::{CouncilError, Event};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Most terms in a precedent or a query.
const MAX_TERMS: usize = 16;
/// Most precedent ids a memory hash can bind (the largest `k`).
const MAX_IDS: usize = 5;

fn bad(what: &str) -> CouncilError {
    CouncilError::Invalid(what.to_string())
}

/// True if `s` holds a canary token in any letter case (a lower-cased canary is still a canary).
fn has_canary(s: &str) -> bool {
    s.to_ascii_lowercase()
        .contains(&entropa_synthetic::CANARY_PREFIX.to_ascii_lowercase())
}

/// An id or a tenant: a token without a canary.
pub(crate) fn is_name(s: &str) -> bool {
    is_token(s) && !has_canary(s)
}

/// A term is `field=value`, exactly one `=`, both sides non-empty, characters `a-z0-9._-` only, no canary.
fn is_term(t: &str) -> bool {
    let mut parts = t.split('=');
    let (Some(field), Some(value), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let ok = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
    };
    ok(field) && ok(value) && !has_canary(t)
}

/// Sorted (byte order), duplicate-free, 1..=16 well-formed terms, or an error naming what is wrong.
fn clean_terms(terms: &[String]) -> Result<Vec<String>, CouncilError> {
    if terms.is_empty() || terms.len() > MAX_TERMS {
        return Err(bad("a term list holds 1 to 16 terms"));
    }
    if !terms.iter().all(|t| is_term(t)) {
        return Err(bad("a term is malformed"));
    }
    let set: BTreeSet<&String> = terms.iter().collect();
    if set.len() != terms.len() {
        return Err(bad("a term is repeated"));
    }
    Ok(set.into_iter().cloned().collect())
}

/// Field weights and the abstention threshold of the lexical scorer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalConfig {
    /// Integer weight per field name (the text before `=` in a term); a field not listed weighs 1.
    pub weights: Vec<(String, u32)>,
    /// A precedent scoring below this (per mille) is not returned.
    pub threshold: u32,
}

impl Default for LexicalConfig {
    /// class 4, decision 3, severity 2, change 2, reason 1; threshold 400.
    fn default() -> Self {
        LexicalConfig {
            weights: [
                ("class", 4),
                ("decision", 3),
                ("severity", 2),
                ("change", 2),
                ("reason", 1),
            ]
            .into_iter()
            .map(|(k, w)| (k.to_string(), w))
            .collect(),
            threshold: 400,
        }
    }
}

/// One admitted precedent: its id, its tenant and its sorted closed-code terms (`field=value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Precedent {
    /// Precedent id (a token).
    pub id: String,
    /// The tenant whose agents may retrieve it.
    pub tenant: String,
    /// The terms, for example `class=missing_approval`.
    pub terms: Vec<String>,
}

/// A retrieval hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexHit {
    /// Precedent id.
    pub id: String,
    /// `floor(1000 * W(q & d) / W(q | d))`.
    pub score: u32,
}

/// An exact lexical index over admitted, non-revoked precedents.
#[derive(Debug)]
pub struct LexicalIndex {
    weights: BTreeMap<String, u32>,
    threshold: u32,
    /// Sorted by id (byte order); each term list is sorted.
    entries: Vec<Precedent>,
    index_hash: String,
    manifest_hash: String,
}

/// The sorted terms of a precedent from the finding and the accepted decision it came from: `change`, `class`,
/// `decision`, `reason` and `severity` (never `attested`, never a reference or a hash).
pub fn precedent_terms(finding: &Event, decision: &Event) -> Result<Vec<String>, CouncilError> {
    if finding.event_type() != "finding.submitted" || decision.event_type() != "decision.recorded" {
        return Err(bad("a finding and its decision are needed, in that order"));
    }
    if decision.str_field("decision") != Some("accept") {
        return Err(bad("only an accepted decision becomes a precedent"));
    }
    if finding.str_field("finding_id") != decision.str_field("finding_id")
        || finding.session_id() != decision.session_id()
    {
        return Err(bad("the decision belongs to another finding"));
    }
    let field = |e: &Event, k: &str| e.str_field(k).unwrap_or_default().to_string();
    let terms = vec![
        format!("change={}", field(decision, "change_kind")),
        format!("class={}", field(finding, "class")),
        format!("decision={}", field(decision, "decision")),
        format!("reason={}", field(decision, "reason")),
        format!("severity={}", field(finding, "severity")),
    ];
    clean_terms(&terms)
}

fn part(h: &mut blake3::Hasher, s: &str) {
    h.update(&(s.len() as u32).to_be_bytes());
    h.update(s.as_bytes());
}

fn sorted_ids(ids: &[String]) -> Vec<&str> {
    let mut v: Vec<&str> = ids.iter().map(String::as_str).collect();
    v.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    v
}

impl LexicalIndex {
    /// Build an index; precedents whose id is in `revoked` are left out. Refused: no precedent left, a duplicate or
    /// malformed id or tenant, no term, a malformed term, a canary token anywhere.
    pub fn build(
        config: LexicalConfig,
        precedents: Vec<Precedent>,
        revoked: &[String],
    ) -> Result<LexicalIndex, CouncilError> {
        let mut weights = BTreeMap::new();
        for (field, w) in &config.weights {
            if !is_term(&format!("{field}=x")) || *w == 0 {
                return Err(bad(
                    "a field weight needs a field name and a weight above 0",
                ));
            }
            weights.insert(field.clone(), *w);
        }
        if !revoked.iter().all(|r| is_name(r)) {
            return Err(bad("a revoked id is malformed"));
        }
        let revoked_set: BTreeSet<&str> = revoked.iter().map(String::as_str).collect();
        let mut seen = BTreeSet::new();
        let mut entries = Vec::new();
        for p in precedents {
            if !is_name(&p.id) || !is_name(&p.tenant) {
                return Err(bad("a precedent id or tenant is malformed"));
            }
            if !seen.insert(p.id.clone()) {
                return Err(bad("two precedents share an id"));
            }
            let terms = clean_terms(&p.terms)?;
            if !revoked_set.contains(p.id.as_str()) {
                entries.push(Precedent { terms, ..p });
            }
        }
        if entries.is_empty() {
            return Err(bad("no precedent is left to index"));
        }
        entries.sort_unstable_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
        let admitted: Vec<String> = entries.iter().map(|p| p.id.clone()).collect();
        let revoked_list: Vec<String> = revoked_set.iter().map(|s| (*s).to_string()).collect();
        let descriptor = canonical(&json!({"threshold": config.threshold, "weights": weights}));
        let mut h = blake3::Hasher::new();
        h.update(b"entropa-council-index-l-v1\0");
        part(&mut h, &descriptor);
        h.update(&(entries.len() as u32).to_be_bytes());
        for p in &entries {
            part(&mut h, &p.id);
            part(&mut h, &p.tenant);
            h.update(&(p.terms.len() as u32).to_be_bytes());
            for t in &p.terms {
                part(&mut h, t);
            }
        }
        Ok(LexicalIndex {
            weights,
            threshold: config.threshold,
            index_hash: hex::encode(h.finalize().as_bytes()),
            manifest_hash: manifest_hash(&admitted, &revoked_list),
            entries,
        })
    }
    /// Number of precedents in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// True if the index holds no precedent.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// `BLAKE3("entropa-council-index-l-v1" 0x00 || scorer descriptor || precedents with tenant and terms)`, hex.
    pub fn index_hash(&self) -> String {
        self.index_hash.clone()
    }
    /// The manifest hash of this index: its admitted ids and the revoked ids it was built with.
    pub fn manifest_hash(&self) -> String {
        self.manifest_hash.clone()
    }

    fn weight(&self, term: &str) -> u64 {
        let field = term.split('=').next().unwrap_or_default();
        u64::from(self.weights.get(field).copied().unwrap_or(1))
    }

    /// `floor(1000 * W(q & d) / W(q | d))` over two sorted, duplicate-free term lists.
    fn score(&self, query: &[String], doc: &[String]) -> u32 {
        let (mut inter, mut union) = (0u64, 0u64);
        for t in query {
            let w = self.weight(t);
            union += w;
            if doc.binary_search(t).is_ok() {
                inter += w;
            }
        }
        union += doc
            .iter()
            .filter(|t| query.binary_search(t).is_err())
            .map(|t| self.weight(t))
            .sum::<u64>();
        if union == 0 {
            return 0;
        }
        u32::try_from(1000 * inter / union).unwrap_or(1000)
    }

    /// Exact retrieval inside one tenant, best first, ties by id, below-threshold results dropped; `k` is 1..=5.
    pub fn search(
        &self,
        tenant: &str,
        query: &[String],
        k: usize,
    ) -> Result<Vec<LexHit>, CouncilError> {
        if k == 0 || k > MAX_IDS {
            return Err(CouncilError::Limit("k is 1 to 5".into()));
        }
        if !is_name(tenant) {
            return Err(bad("the tenant is malformed"));
        }
        let query = clean_terms(query)?;
        let mut hits: Vec<LexHit> = self
            .entries
            .iter()
            .filter(|p| p.tenant == tenant)
            .map(|p| LexHit {
                id: p.id.clone(),
                score: self.score(&query, &p.terms),
            })
            .filter(|h| h.score >= self.threshold)
            .collect();
        // entries are in id order and the sort is stable, so equal scores keep the lower id first
        hits.sort_by_key(|h| std::cmp::Reverse(h.score));
        hits.truncate(k);
        Ok(hits)
    }
}

/// `BLAKE3("entropa-council-manifest-v1" 0x00 || sorted admitted ids || sorted revoked ids)`, hex.
pub fn manifest_hash(admitted: &[String], revoked: &[String]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-council-manifest-v1\0");
    for group in [admitted, revoked] {
        h.update(&(group.len() as u32).to_be_bytes());
        for id in sorted_ids(group) {
            part(&mut h, id);
        }
    }
    hex::encode(h.finalize().as_bytes())
}

/// `BLAKE3("entropa-council-memory-v1" 0x00 || index_hash || sorted ids)`, hex: binds a decision to the precedents it saw.
pub fn memory_hash(index_hash: &str, ids: &[String]) -> Result<String, CouncilError> {
    if !is_hex(index_hash, 64) {
        return Err(bad("the index hash is not 64 lower-case hex characters"));
    }
    if ids.is_empty() {
        return Err(bad("a memory hash binds at least one precedent"));
    }
    if ids.len() > MAX_IDS {
        return Err(CouncilError::Limit(
            "a memory hash binds at most 5 ids".into(),
        ));
    }
    if !ids.iter().all(|i| is_name(i)) {
        return Err(bad("a precedent id is malformed"));
    }
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(bad("a precedent id is repeated"));
    }
    let mut h = blake3::Hasher::new();
    h.update(b"entropa-council-memory-v1\0");
    h.update(index_hash.as_bytes());
    for id in sorted_ids(ids) {
        part(&mut h, id);
    }
    Ok(hex::encode(h.finalize().as_bytes()))
}
