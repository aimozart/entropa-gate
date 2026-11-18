//! Sealing: a corpus spec plus the source files become a version directory (a hashed manifest and the clauses). Versions are never
//! overwritten: the same content again is a no-op, different content under the same version name is refused.

use crate::chunk::{self, Format};
use crate::corpus::{text_sha256, Clause, ClauseEntry, Manifest, SourceEntry, Tier};
use crate::records::{EvidenceRequest, RecordSink};
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// One source in a corpus spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpec {
    /// Standard name.
    pub standard: String,
    /// Standard version.
    pub std_version: String,
    /// Licence tier.
    pub tier: Tier,
    /// Chunker format.
    pub format: Format,
    /// File name inside the source directory.
    pub file: String,
    /// The sha256 the source file must have (hex).
    pub sha256: String,
}

/// A corpus spec: the version name and its pinned sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusSpec {
    /// The corpus version name.
    pub corpus_version: String,
    /// The sources.
    pub sources: Vec<SourceSpec>,
}

/// Why sealing or opening failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// A changed source or a changed version content: refused, nothing overwritten.
    Refused(String),
    /// A sealed version no longer matches its own hashes.
    Tampered(String),
    /// No such sealed version.
    Missing(String),
    /// A source could not be read or chunked.
    Source(String),
    /// The spec is malformed.
    Spec(String),
    /// A file system error.
    Io(String),
    /// The corpus was sealed but its receipt could not be written.
    Receipt(String),
}

/// The result of a seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealOutcome {
    /// A new version was sealed.
    Created {
        /// The corpus hash.
        corpus_hash: String,
        /// Clauses sealed.
        clauses: usize,
        /// Sources sealed.
        sources: usize,
    },
    /// The same content was already sealed under this name; nothing changed.
    AlreadySealed {
        /// The corpus hash.
        corpus_hash: String,
    },
}

/// A sealed version opened and re-verified.
#[derive(Debug, Clone)]
pub struct Sealed {
    /// The manifest.
    pub manifest: Manifest,
    /// The clauses, with text.
    pub clauses: Vec<Clause>,
}

#[derive(Deserialize)]
struct RawSource {
    standard: String,
    std_version: String,
    tier: String,
    format: String,
    file: String,
    sha256: String,
}
#[derive(Deserialize)]
struct RawSpec {
    corpus_version: String,
    sources: Vec<RawSource>,
}

fn name_ok(s: &str, max: usize) -> bool {
    Regex::new(&format!(r"^[A-Za-z0-9][A-Za-z0-9._-]{{0,{}}}$", max - 1))
        .is_ok_and(|r| r.is_match(s))
        && !s.contains("..")
}

/// Parse and validate a corpus spec (JSON). Nothing is read or written.
pub fn parse_spec(json: &str) -> Result<CorpusSpec, SealError> {
    let raw: RawSpec = serde_json::from_str(json)
        .map_err(|_| SealError::Spec("not a valid corpus spec".into()))?;
    if !name_ok(&raw.corpus_version, 64) {
        return Err(SealError::Spec(
            "corpus_version must be 1 to 64 characters of letters, digits, dot, dash or underscore"
                .into(),
        ));
    }
    if raw.sources.is_empty() {
        return Err(SealError::Spec("a corpus needs at least one source".into()));
    }
    let hex64 = Regex::new(r"^[0-9a-f]{64}$").map_err(|_| SealError::Spec("internal".into()))?;
    let mut sources = Vec::new();
    for s in raw.sources {
        if !name_ok(&s.standard, 64) || !name_ok(&s.std_version, 32) {
            return Err(SealError::Spec(
                "standard and std_version must be plain names".into(),
            ));
        }
        let tier = Tier::parse(&s.tier)
            .ok_or_else(|| SealError::Spec("tier must be OPEN or LICENSED".into()))?;
        let format =
            Format::parse(&s.format).ok_or_else(|| SealError::Spec("unknown format".into()))?;
        if s.file.is_empty()
            || s.file.contains('/')
            || s.file.contains('\\')
            || s.file.contains("..")
            || s.file.starts_with('.')
        {
            return Err(SealError::Spec(
                "file must be a plain file name inside the source directory".into(),
            ));
        }
        if !hex64.is_match(&s.sha256) {
            return Err(SealError::Spec(
                "sha256 must be 64 lowercase hex characters".into(),
            ));
        }
        if sources
            .iter()
            .any(|x: &SourceSpec| x.standard == s.standard && x.std_version == s.std_version)
        {
            return Err(SealError::Spec(
                "the same standard and version appears twice".into(),
            ));
        }
        sources.push(SourceSpec {
            standard: s.standard,
            std_version: s.std_version,
            tier,
            format,
            file: s.file,
            sha256: s.sha256,
        });
    }
    Ok(CorpusSpec {
        corpus_version: raw.corpus_version,
        sources,
    })
}

fn request(
    label_allow: bool,
    version: &str,
    hash: &str,
    total: u64,
    passed: u64,
    flagged: u64,
    why: &str,
) -> EvidenceRequest {
    EvidenceRequest {
        kind: "evidence.change".into(),
        label: "corpus_version".into(),
        decision: if label_allow { "allow" } else { "deny" }.into(),
        reason: if label_allow {
            "check_passed"
        } else {
            "check_failed"
        }
        .into(),
        control: "nist_800_53_au_9".into(),
        total,
        passed,
        flagged,
        detail: format!("version={version}|corpus_hash={hash}|{why}"),
        run_id: if label_allow {
            format!("corpus-{version}")
        } else {
            format!("corpus-{version}-refused")
        },
    }
}

fn refuse(
    sink: Option<&dyn RecordSink>,
    version: &str,
    hash: &str,
    total: usize,
    changed: usize,
    msg: String,
) -> SealError {
    let changed = changed.max(1);
    let total = total.max(changed);
    if let Some(s) = sink {
        let _ = s.emit(&request(
            false,
            version,
            hash,
            total as u64,
            (total - changed) as u64,
            changed as u64,
            "refused",
        ));
    }
    SealError::Refused(msg)
}

/// Seal a corpus version. `extractor` turns a `.pdf` source into text. `sink`, when given, receives one `corpus_version` record.
pub fn seal(
    spec: &CorpusSpec,
    source_dir: &Path,
    store_dir: &Path,
    extractor: &dyn Fn(&Path) -> Result<String, String>,
    sink: Option<&dyn RecordSink>,
) -> Result<SealOutcome, SealError> {
    let v = &spec.corpus_version;
    // 1. every source must be the file the spec pins
    let mut changed = 0usize;
    let mut texts: Vec<(usize, String, String)> = Vec::new();
    for (i, s) in spec.sources.iter().enumerate() {
        let path = source_dir.join(&s.file);
        let bytes = std::fs::read(&path)
            .map_err(|_| SealError::Source(format!("cannot read {}", s.file)))?;
        let sha = hex::encode(Sha256::digest(&bytes));
        if sha != s.sha256 {
            changed += 1;
        }
        let text = if s.file.to_lowercase().ends_with(".pdf") {
            if sha != s.sha256 {
                String::new()
            } else {
                extractor(&path)
                    .map_err(|e| SealError::Source(format!("cannot extract {}: {e}", s.file)))?
            }
        } else {
            String::from_utf8(bytes)
                .map_err(|_| SealError::Source(format!("{} is not UTF-8 text", s.file)))?
        };
        texts.push((i, sha, text));
    }
    if changed > 0 {
        return Err(refuse(sink, v, "none", spec.sources.len(), changed, format!("{changed} source file(s) differ from the sha256 pinned in the spec; nothing was sealed")));
    }
    // 2. chunk
    let mut clauses: Vec<Clause> = Vec::new();
    let mut sources: Vec<SourceEntry> = Vec::new();
    for (i, sha, text) in &texts {
        let s = &spec.sources[*i];
        let raw = chunk::chunk(s.format, text)
            .map_err(|e| SealError::Source(format!("{}: {}", s.file, e.0)))?;
        sources.push(SourceEntry {
            standard: s.standard.clone(),
            std_version: s.std_version.clone(),
            tier: s.tier,
            format: s.format.as_str().into(),
            file: s.file.clone(),
            source_sha256: sha.clone(),
            clauses: raw.len(),
        });
        for c in raw {
            clauses.push(Clause {
                standard: s.standard.clone(),
                std_version: s.std_version.clone(),
                id: c.id,
                tier: s.tier,
                text_sha256: text_sha256(&c.text),
                text: c.text,
            });
        }
    }
    sources.sort_by(|a, b| (&a.standard, &a.std_version).cmp(&(&b.standard, &b.std_version)));
    clauses.sort_by(|a, b| (&a.standard, &a.id).cmp(&(&b.standard, &b.id)));
    let entries: Vec<ClauseEntry> = clauses
        .iter()
        .map(|c| ClauseEntry {
            standard: c.standard.clone(),
            id: c.id.clone(),
            text_sha256: c.text_sha256.clone(),
        })
        .collect();
    let corpus_hash = Manifest::compute_hash(v, &sources, &entries);
    let manifest = Manifest {
        corpus_version: v.clone(),
        corpus_hash: corpus_hash.clone(),
        sources,
        clauses: entries,
    };
    // 3. never overwrite
    let dir = store_dir.join(v);
    if dir.exists() {
        let old = std::fs::read_to_string(dir.join("manifest.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<Manifest>(&t).ok());
        return match old {
            Some(m) if m.corpus_hash == corpus_hash => {
                Ok(SealOutcome::AlreadySealed { corpus_hash })
            }
            Some(m) => {
                let differing = manifest
                    .sources
                    .iter()
                    .filter(|s| {
                        !m.sources.iter().any(|o| {
                            o.standard == s.standard
                                && o.std_version == s.std_version
                                && o.source_sha256 == s.source_sha256
                        })
                    })
                    .count();
                Err(refuse(sink, v, &corpus_hash, manifest.sources.len(), differing, format!("version {v} is already sealed with different content; nothing was overwritten")))
            }
            None => Err(refuse(
                sink,
                v,
                &corpus_hash,
                manifest.sources.len(),
                1,
                format!(
                    "version {v} exists but its manifest cannot be read; nothing was overwritten"
                ),
            )),
        };
    }
    std::fs::create_dir_all(store_dir).map_err(|e| SealError::Io(e.to_string()))?;
    let tmp: PathBuf = store_dir.join(format!(".tmp-{v}-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| SealError::Io(e.to_string()))?;
    let jsonl: Vec<String> = clauses
        .iter()
        .filter_map(|c| serde_json::to_string(c).ok())
        .collect();
    let write = || -> std::io::Result<()> {
        std::fs::write(
            tmp.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap_or_default() + "\n",
        )?;
        std::fs::write(tmp.join("clauses.jsonl"), jsonl.join("\n") + "\n")?;
        std::fs::rename(&tmp, &dir)
    };
    write().map_err(|e| SealError::Io(e.to_string()))?;
    let outcome = SealOutcome::Created {
        corpus_hash: corpus_hash.clone(),
        clauses: clauses.len(),
        sources: manifest.sources.len(),
    };
    if let Some(s) = sink {
        s.emit(&request(
            true,
            v,
            &corpus_hash,
            clauses.len() as u64,
            manifest.sources.len() as u64,
            0,
            &format!(
                "clauses={}|sources={}",
                clauses.len(),
                manifest.sources.len()
            ),
        ))
        .map_err(|e| {
            SealError::Receipt(format!(
                "the corpus is sealed but its receipt was not written: {e}"
            ))
        })?;
    }
    Ok(outcome)
}

/// The sealed versions in a store, sorted.
pub fn list_versions(store_dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(store_dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| e.path().join("manifest.json").is_file())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Open a sealed version and re-verify every hash.
pub fn open(store_dir: &Path, version: &str) -> Result<Sealed, SealError> {
    if !name_ok(version, 64) {
        return Err(SealError::Missing(format!("no such version: {version:?}")));
    }
    let dir = store_dir.join(version);
    let mtext = std::fs::read_to_string(dir.join("manifest.json"))
        .map_err(|_| SealError::Missing(format!("no sealed version {version}")))?;
    let manifest: Manifest = serde_json::from_str(&mtext)
        .map_err(|_| SealError::Tampered("the manifest cannot be read".into()))?;
    if manifest.corpus_version != version
        || Manifest::compute_hash(
            &manifest.corpus_version,
            &manifest.sources,
            &manifest.clauses,
        ) != manifest.corpus_hash
    {
        return Err(SealError::Tampered(
            "the manifest does not match its corpus hash".into(),
        ));
    }
    let ctext = std::fs::read_to_string(dir.join("clauses.jsonl"))
        .map_err(|_| SealError::Tampered("the clauses file is missing".into()))?;
    let mut clauses: Vec<Clause> = Vec::new();
    for line in ctext.lines().filter(|l| !l.trim().is_empty()) {
        let c: Clause = serde_json::from_str(line)
            .map_err(|_| SealError::Tampered("a clause line cannot be read".into()))?;
        if text_sha256(&c.text) != c.text_sha256 {
            return Err(SealError::Tampered(format!(
                "clause {} {} does not match its text hash",
                c.standard, c.id
            )));
        }
        clauses.push(c);
    }
    // the clause's own version and licence tier are not in the clause hash: they must agree with the manifest's source for that standard
    // (a licensed clause relabelled open would return its full text), and each source's clause count must be the number of its clauses
    for c in &clauses {
        let ok = manifest.sources.iter().any(|s| {
            s.standard == c.standard && s.std_version == c.std_version && s.tier == c.tier
        });
        if !ok {
            return Err(SealError::Tampered(format!(
                "clause {} {} disagrees with the manifest about its version or licence tier",
                c.standard, c.id
            )));
        }
    }
    for s in &manifest.sources {
        let n = clauses
            .iter()
            .filter(|c| c.standard == s.standard && c.std_version == s.std_version)
            .count();
        if n != s.clauses {
            return Err(SealError::Tampered(format!(
                "source {} {} lists {} clauses but the store holds {}",
                s.standard, s.std_version, s.clauses, n
            )));
        }
    }
    let from_file: Vec<ClauseEntry> = clauses
        .iter()
        .map(|c| ClauseEntry {
            standard: c.standard.clone(),
            id: c.id.clone(),
            text_sha256: c.text_sha256.clone(),
        })
        .collect();
    if from_file != manifest.clauses {
        return Err(SealError::Tampered(
            "the clauses do not match the manifest".into(),
        ));
    }
    Ok(Sealed { manifest, clauses })
}
