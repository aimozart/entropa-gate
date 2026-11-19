//! Decision memory: pinned, hashed, exact retrieval and provenance records (the council design notes section 12).

use crate::canon::canonical;
use crate::event::{is_token, validate};
use crate::render::line;
use crate::{CouncilError, Event};
use serde_json::json;
use std::collections::BTreeMap;

/// The pinned embedding model descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDescriptor {
    /// Model id string.
    pub id: String,
    /// Vector dimension.
    pub dim: usize,
    /// Normalisation label, for example `unit`.
    pub normalization: String,
}

/// A precedent admitted to the corpus (only signed, accepted ledger entries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Precedent id.
    pub id: String,
    rendering: String,
}

impl Entry {
    /// The deterministic closed-code rendering that gets embedded (never vault text).
    pub fn rendering(&self) -> &str {
        &self.rendering
    }
}

/// A retrieval hit.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// Precedent id.
    pub id: String,
    /// Cosine similarity.
    pub score: f64,
}

/// An exact, pinned index.
#[derive(Debug)]
pub struct Index {
    model: ModelDescriptor,
    entries: BTreeMap<String, Vec<f32>>,
}

fn bad(what: &str) -> CouncilError {
    CouncilError::Invalid(what.to_string())
}

/// Admit a decision to the corpus: it must be an accepted `decision.recorded` event that a human accepted and whose
/// signature verified; the embedded text is rendered from closed codes only.
pub fn admit(
    decision: &Event,
    accepted_by_human: bool,
    signature_ok: bool,
) -> Result<Entry, CouncilError> {
    if decision.event_type() != "decision.recorded"
        || decision.str_field("decision") != Some("accept")
    {
        return Err(bad("only an accepted decision becomes a precedent"));
    }
    if !accepted_by_human {
        return Err(bad("the decision was not accepted by the human"));
    }
    if !signature_ok {
        return Err(CouncilError::Verify(
            "the decision's signature did not verify".into(),
        ));
    }
    let finding = decision.str_field("finding_id").unwrap_or_default();
    let session = decision.session_id().unwrap_or_default();
    let mut id = format!("{}:{finding}", session.get(..16).unwrap_or(session));
    if id.len() > 64 {
        id = format!("h:{}", session.get(..16).unwrap_or(session));
    }
    let rendering = line(decision)
        .map(|l| format!("{l}\n"))
        .ok_or_else(|| bad("not renderable"))?;
    Ok(Entry { id, rendering })
}

impl Index {
    /// Build an index. Refused: dimension mismatch, duplicate, empty or malformed ids, non-finite values, no entries.
    pub fn build(
        model: ModelDescriptor,
        entries: Vec<(String, Vec<f32>)>,
    ) -> Result<Index, CouncilError> {
        if model.dim == 0
            || !is_token(&model.id)
            || !is_token(&model.normalization)
            || entries.is_empty()
        {
            return Err(bad("the model descriptor or the entry list is invalid"));
        }
        let mut map = BTreeMap::new();
        for (id, v) in entries {
            if !is_token(&id)
                || id.contains(entropa_synthetic::CANARY_PREFIX)
                || v.len() != model.dim
                || v.iter().any(|x| !x.is_finite())
            {
                return Err(bad("an entry is invalid"));
            }
            if map.insert(id, v).is_some() {
                return Err(bad("two entries share an id"));
            }
        }
        Ok(Index {
            model,
            entries: map,
        })
    }

    /// `BLAKE3("entropa-council-index-v1" 0x00 || model descriptor || sorted (id, vector bytes))`, hex.
    pub fn index_hash(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"entropa-council-index-v1\0");
        let part = |h: &mut blake3::Hasher, s: &str| {
            h.update(&(s.len() as u32).to_be_bytes());
            h.update(s.as_bytes());
        };
        part(&mut h, &self.model.id);
        h.update(&(self.model.dim as u32).to_be_bytes());
        part(&mut h, &self.model.normalization);
        h.update(&(self.entries.len() as u32).to_be_bytes());
        for (id, v) in &self.entries {
            part(&mut h, id);
            for x in v {
                h.update(&x.to_le_bytes());
            }
        }
        hex::encode(h.finalize().as_bytes())
    }

    /// Exact cosine search, best first, ties broken by id; `k` must be 1..=5.
    pub fn search(&self, query: &[f32], k: usize) -> Result<Vec<Hit>, CouncilError> {
        if !(1..=5).contains(&k) {
            return Err(CouncilError::Limit("k must be from 1 to 5".into()));
        }
        if query.len() != self.model.dim || query.iter().any(|x| !x.is_finite()) {
            return Err(bad("the query does not fit the index"));
        }
        let norm = |v: &[f32]| {
            v.iter()
                .map(|x| f64::from(*x) * f64::from(*x))
                .sum::<f64>()
                .sqrt()
        };
        let qn = norm(query);
        if qn == 0.0 {
            return Err(bad("the query is the zero vector"));
        }
        let mut hits: Vec<Hit> = self
            .entries
            .iter()
            .map(|(id, v)| {
                let vn = norm(v);
                let dot: f64 = query
                    .iter()
                    .zip(v)
                    .map(|(a, b)| f64::from(*a) * f64::from(*b))
                    .sum();
                Hit {
                    id: id.clone(),
                    score: if vn == 0.0 { 0.0 } else { dot / (qn * vn) },
                }
            })
            .collect();
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
        hits.truncate(k);
        Ok(hits)
    }
}

/// The unsigned `precedent.referenced` event JSON for a retrieval: ids must come from `hits`, which must come from
/// `index`; at most 5. The `alg` label is `ML-DSA-65`, the only algorithm entropa-core has; a caller that signs with
/// another algorithm sets the label before signing (`sign_event` checks it against the signer).
pub fn precedent_reference(
    index: &Index,
    decision_ref: &str,
    hits: &[Hit],
    followed: &str,
    actor: &str,
    ts: u64,
) -> Result<String, CouncilError> {
    if hits.is_empty() {
        return Err(bad(
            "a retrieval that returned nothing records no reference",
        ));
    }
    if hits.len() > 5 {
        return Err(CouncilError::Limit(
            "at most 5 precedents are referenced".into(),
        ));
    }
    if hits.iter().any(|h| !index.entries.contains_key(&h.id)) {
        return Err(bad("a hit is not in the index"));
    }
    let v = json!({
        "v": 1, "type": "precedent.referenced", "alg": "ML-DSA-65", "actor": actor, "ts": ts, "decision_ref": decision_ref,
        "index_hash": index.index_hash(), "precedent_ids": hits.iter().map(|h| h.id.clone()).collect::<Vec<_>>(),
        "k": hits.len(), "followed": followed,
    });
    validate(&v, false)?;
    Ok(canonical(&v))
}
