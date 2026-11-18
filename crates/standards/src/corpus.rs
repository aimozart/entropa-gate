//! Corpus types: tiers, clauses and the sealed manifest.

use serde::{Deserialize, Serialize};

/// Licence tier of a source. OPEN text may be quoted in full; LICENSED text stays in the local store and outputs are limited to a short quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Tier {
    /// Openly published text (NIST OSCAL, Official Journal, public regulation text).
    Open,
    /// Licensed text (for example PCI DSS): indexed locally, never copied into a repository.
    Licensed,
}

impl Tier {
    /// The wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Open => "OPEN",
            Tier::Licensed => "LICENSED",
        }
    }
    /// Parse a wire string.
    pub fn parse(s: &str) -> Option<Tier> {
        match s {
            "OPEN" => Some(Tier::Open),
            "LICENSED" => Some(Tier::Licensed),
            _ => None,
        }
    }
}

/// One clause of one standard version, with its text and the sha256 of that text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Clause {
    /// Standard name, for example `NIST-SP-800-53`.
    pub standard: String,
    /// The standard's own version, for example `5.2.0`.
    pub std_version: String,
    /// Clause id, for example `AU-9(3)`, `Art.12` or `10.3.4`.
    pub id: String,
    /// Licence tier of the source.
    pub tier: Tier,
    /// The clause text (kept only in the local sealed store).
    pub text: String,
    /// sha256 of `text` (hex).
    pub text_sha256: String,
}

/// One source file in a sealed corpus version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEntry {
    /// Standard name.
    pub standard: String,
    /// Standard version.
    pub std_version: String,
    /// Licence tier.
    pub tier: Tier,
    /// Chunker format name.
    pub format: String,
    /// Source file name (no path).
    pub file: String,
    /// sha256 of the source file (hex).
    pub source_sha256: String,
    /// Number of clauses taken from it.
    pub clauses: usize,
}

/// A clause in the manifest: id and text hash only, never text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClauseEntry {
    /// Standard name.
    pub standard: String,
    /// Clause id.
    pub id: String,
    /// sha256 of the clause text (hex).
    pub text_sha256: String,
}

/// The sealed manifest of a corpus version: hashes and counts, no clause text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The corpus version name.
    pub corpus_version: String,
    /// sha256 over the canonical form of everything below (hex).
    pub corpus_hash: String,
    /// Sources, ordered by standard and version.
    pub sources: Vec<SourceEntry>,
    /// Clauses, ordered by standard and id.
    pub clauses: Vec<ClauseEntry>,
}

#[derive(Serialize)]
struct HashInput<'a> {
    corpus_version: &'a str,
    sources: &'a [SourceEntry],
    clauses: &'a [ClauseEntry],
}

impl Manifest {
    /// The corpus hash this content must have (does not read `self.corpus_hash`).
    pub fn compute_hash(
        corpus_version: &str,
        sources: &[SourceEntry],
        clauses: &[ClauseEntry],
    ) -> String {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(&HashInput {
            corpus_version,
            sources,
            clauses,
        })
        .unwrap_or_default();
        hex::encode(Sha256::digest(bytes))
    }
}

/// sha256 of text, hex.
pub fn text_sha256(text: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(text.as_bytes()))
}
