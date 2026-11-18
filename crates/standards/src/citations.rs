//! Citation-bound guardrails (R1 task 5). A register row or a guardrail cites a clause by (standard, clause id) together with the sha256 of the
//! clause text in a named corpus version. Checking is an exact lookup by id in a sealed manifest and a comparison of hashes; it is deterministic
//! and never searches. If a cited clause's text changes in a newer corpus version the check reports drift.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// A cited clause.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Ref {
    /// Standard name.
    pub standard: String,
    /// Clause id.
    pub clause: String,
    /// sha256 of the clause text when it was cited.
    pub text_sha256: String,
}

/// An E1 register row bound to a clause.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RegRow {
    /// The E1 register id.
    pub register_id: String,
    /// The cited clause (flattened in the JSON).
    #[serde(flatten)]
    pub cite: Ref,
}

/// A real guardrail of ours and the clauses it cites.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Guardrail {
    /// Guardrail id.
    pub id: String,
    /// `cedar_rule`, `input_validation` or `canary_scan`.
    pub kind: String,
    /// The file that holds it, relative to the repository root.
    pub file: String,
    /// A line that must appear in that file (so a moved or deleted guardrail is noticed).
    pub marker: String,
    /// The clauses it cites.
    pub cites: Vec<Ref>,
}

/// The whole citations file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Citations {
    /// Format version (1).
    pub citations_version: u32,
    /// The corpus version the hashes were taken from.
    pub corpus_version: String,
    /// That version's corpus hash.
    pub corpus_hash: String,
    /// The register rows.
    pub register_rows: Vec<RegRow>,
    /// The guardrails.
    pub guardrails: Vec<Guardrail>,
}

impl Citations {
    /// Every cited clause, register rows first.
    pub fn all_refs(&self) -> Vec<&Ref> {
        self.register_rows
            .iter()
            .map(|r| &r.cite)
            .chain(self.guardrails.iter().flat_map(|g| g.cites.iter()))
            .collect()
    }
}

/// One problem found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The clause exists but its text hash differs from the cited one.
    Drift {
        /// Register id or guardrail id.
        subject: String,
        /// Standard.
        standard: String,
        /// Clause id.
        clause: String,
        /// The hash that was cited.
        cited: String,
        /// The hash the clause has now.
        current: String,
    },
    /// The cited clause is not in the corpus version.
    Unknown {
        /// Register id or guardrail id.
        subject: String,
        /// Standard.
        standard: String,
        /// Clause id.
        clause: String,
    },
    /// The guardrail's file does not exist.
    MissingSubject {
        /// Guardrail id.
        subject: String,
        /// The file.
        file: String,
    },
    /// The guardrail's file exists but the marker line is gone.
    MarkerMissing {
        /// Guardrail id.
        subject: String,
        /// The file.
        file: String,
    },
}

impl Finding {
    /// The register id or guardrail id the finding is about.
    pub fn subject(&self) -> &str {
        match self {
            Finding::Drift { subject, .. }
            | Finding::Unknown { subject, .. }
            | Finding::MissingSubject { subject, .. }
            | Finding::MarkerMissing { subject, .. } => subject,
        }
    }
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse and validate a citations file.
pub fn parse(json: &str) -> Result<Citations, String> {
    let c: Citations =
        serde_json::from_str(json).map_err(|e| format!("not a valid citations file: {e}"))?;
    if c.citations_version != 1 {
        return Err("unsupported citations_version".into());
    }
    if c.corpus_version.is_empty() || c.corpus_hash.is_empty() {
        return Err("the corpus version and hash are required".into());
    }
    if c.all_refs()
        .iter()
        .any(|r| !hex64(&r.text_sha256) || r.standard.is_empty() || r.clause.is_empty())
    {
        return Err("every citation needs a standard, a clause id and a 64-hex text hash".into());
    }
    if c.guardrails
        .iter()
        .any(|g| g.cites.is_empty() || g.file.is_empty() || g.marker.is_empty())
    {
        return Err("every guardrail needs a file, a marker and at least one citation".into());
    }
    Ok(c)
}

/// A lookup from (standard, clause id) to the clause's text hash, built from a sealed manifest's JSON.
pub type Lookup = Box<dyn Fn(&str, &str) -> Option<String>>;

/// Build a [`Lookup`] from a sealed manifest's JSON.
pub fn manifest_lookup(manifest_json: &str) -> Result<Lookup, String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json)
        .map_err(|_| "the manifest is not valid JSON".to_string())?;
    let mut map: HashMap<(String, String), String> = HashMap::new();
    for c in v
        .get("clauses")
        .and_then(|c| c.as_array())
        .ok_or("the manifest has no clauses")?
    {
        if let (Some(s), Some(i), Some(h)) = (
            c["standard"].as_str(),
            c["id"].as_str(),
            c["text_sha256"].as_str(),
        ) {
            map.insert((s.to_string(), i.to_string()), h.to_string());
        }
    }
    Ok(Box::new(move |s: &str, i: &str| {
        map.get(&(s.to_string(), i.to_string())).cloned()
    }))
}

/// Compare every citation with the current hash of its clause. An exact lookup by id; no search.
pub fn check(c: &Citations, lookup: &dyn Fn(&str, &str) -> Option<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut one = |subject: &str, r: &Ref| match lookup(&r.standard, &r.clause) {
        None => out.push(Finding::Unknown {
            subject: subject.into(),
            standard: r.standard.clone(),
            clause: r.clause.clone(),
        }),
        Some(now) if !now.eq_ignore_ascii_case(&r.text_sha256) => out.push(Finding::Drift {
            subject: subject.into(),
            standard: r.standard.clone(),
            clause: r.clause.clone(),
            cited: r.text_sha256.clone(),
            current: now,
        }),
        Some(_) => {}
    };
    for r in &c.register_rows {
        one(&r.register_id, &r.cite);
    }
    for g in &c.guardrails {
        for r in &g.cites {
            one(&g.id, r);
        }
    }
    out
}

/// Check that each guardrail's file exists under `root` and still holds its marker line.
pub fn check_subjects(c: &Citations, root: &Path) -> Vec<Finding> {
    c.guardrails
        .iter()
        .filter_map(|g| match std::fs::read_to_string(root.join(&g.file)) {
            Err(_) => Some(Finding::MissingSubject {
                subject: g.id.clone(),
                file: g.file.clone(),
            }),
            Ok(t) if !t.contains(&g.marker) => Some(Finding::MarkerMissing {
                subject: g.id.clone(),
                file: g.file.clone(),
            }),
            Ok(_) => None,
        })
        .collect()
}
