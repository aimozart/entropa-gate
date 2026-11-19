//! Deterministic retrieval over sealed clauses: exact-id hits, BM25 text search, standard scoping, an abstention gate, version pinning,
//! tier-aware output and cite_check. No model, no network, no randomness: the same corpus and query always give the same bytes.

use crate::corpus::{Clause, Tier};
use crate::seal::Sealed;
use crate::text;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// The R1 absolute score floor (kept for the record of the R1 measurement; the R2 gate is relative, see [`Config`]).
pub const SCORE_FLOOR: f64 = 3.0;
/// The R1 term-count coverage floor (kept for the record).
pub const COVERAGE_MIN: f64 = 0.5;
/// BM25 `k1`.
pub const K1: f64 = 1.2;
/// BM25 `b`.
pub const B: f64 = 0.75;
/// Largest clause text returned for an OPEN passage, in characters.
pub const TEXT_CAP: usize = 4000;
/// Words in the single quote returned for a LICENSED passage.
pub const QUOTE_WORDS: usize = 25;
/// Largest number of passages one search returns.
pub const MAX_K: usize = 10;
const MAX_QUERY_CHARS: usize = 2000;
const MAX_TERMS: usize = 64;

/// Retrieval switches. The defaults are the measured configuration; the others exist for ablations and for tests on tiny corpora.
#[derive(Debug, Clone)]
pub struct Config {
    /// Abstain on a query that names a standard we do not hold (a name list; ablation only, off in the shipped configuration).
    pub unindexed_guard: bool,
    /// Scope a query that names a standard to that standard and ignore the name when scoring.
    pub scope_by_standard_name: bool,
    /// Legacy absolute floor on the score of the top passage (0 = off; the relative gate replaces it).
    pub score_floor: f64,
    /// Floor on the idf-weighted share of the query that the top passage covers.
    pub coverage_min: f64,
    /// Floor on the top passage's score as a share of the best score its query could earn (corpus-size independent).
    pub min_norm_score: f64,
    /// The first this-many words of a clause form its head (title) field.
    pub head_words: usize,
    /// Extra term frequency for a query term found in the head field.
    pub head_weight: f64,
    /// A term counts at most this many times in a clause body (stuffing defence).
    pub tf_cap: u32,
    /// A clause counts as at most this many times its standard's median length (length defence).
    pub len_cap_mult: f64,
    /// The score is multiplied by the idf-weighted coverage raised to this power.
    pub cov_exp: f64,
    /// Multiplier for a clause that is long enough but is not prose (almost no function words: a keyword block).
    pub prose_penalty: f64,
    /// Clauses shorter than this many words are never judged for prose.
    pub prose_min_words: usize,
    /// A clause whose share of function words is below this is not prose.
    pub prose_stop_ratio: f64,
    /// Weight of a query word absent from the corpus, as a share of the top idf (0 ignores it).
    pub unknown_weight: f64,
    /// Bonus for each adjacent pair of query words that also sits adjacent in the clause (0 = off), in units of the pair's mean idf.
    pub phrase_weight: f64,
    /// A clause whose id extends another matching clause's id (an enhancement) yields to that parent when the parent scores at least this
    /// share of its score (0 = off).
    pub parent_ratio: f64,
    /// When a clause head holds at least `echo_terms` distinct query terms and the body holds none of them (a heading that echoes the question),
    /// those terms count at this factor.
    pub head_only_factor: f64,
    /// See `head_only_factor`.
    pub echo_terms: usize,
    /// An unknown name weighs this many times the top idf.
    pub entity_mult: f64,
    /// Abstain on a query that names a standard we do not hold, found structurally (an acronym or digit-bearing name followed by a kind word,
    /// or another NIST publication number), never from a list of foreign names.
    pub foreign_guard: bool,
    /// Count an unknown acronym, digit-bearing token or mid-sentence capitalised word at full weight (it names something we do not hold).
    pub entity_guard: bool,
    /// R3: the top passage must hold at least this many DISTINCT content words of the query (function words excluded, stems on); 0 = off.
    pub content_min_matched: usize,
    /// R3: switch the structural clause flags on (statistics of a clause, copies of other clauses, echoes of the query).
    pub structural_flags: bool,
    /// R3: a flagged clause's score is multiplied by this (an excluding flag removes the clause from text search).
    pub flag_factor: f64,
    /// R3: the share of the query's distinct content words that the top passage holds must be at least this; 0 = off.
    pub content_cov_min: f64,
    /// RS1: the shortest clause, in tokens, whose query density is judged (the `dense_keywords` flag). The shipped value is the R3 one (24); a smaller value is an RS1 candidate.
    pub density_min_tokens: usize,
    /// RS1: apply the raw-text structural flags (hidden characters, markup, repeated id). ON by default since the RS1 freeze (a stage record (not published)).
    pub raw_flags: bool,
    /// RS1 candidate: an unknown ALL-CAPS name anywhere in the question (not only before a word like "Act") marks it as about another standard. ON by default since the RS1 freeze.
    pub foreign_any_name: bool,
}

impl Default for Config {
    /// The R2 shipped configuration. Every number was chosen on the DEV sets only (a stage record (not published) records the choice and the DEV results).
    fn default() -> Self {
        Config {
            unindexed_guard: false,
            scope_by_standard_name: true,
            score_floor: 0.0,
            coverage_min: 0.25,
            min_norm_score: 0.1,
            head_words: 8,
            head_weight: 1.0,
            tf_cap: 5,
            len_cap_mult: 8.0,
            cov_exp: 0.0,
            prose_penalty: 0.6,
            prose_min_words: 12,
            prose_stop_ratio: 0.12,
            unknown_weight: 0.5,
            phrase_weight: 2.0,
            parent_ratio: 0.7,
            entity_mult: 2.0,
            head_only_factor: 0.25,
            echo_terms: 5,
            entity_guard: true,
            foreign_guard: true,
            structural_flags: true,
            flag_factor: 0.2,
            content_min_matched: 2,
            content_cov_min: 0.5,
            density_min_tokens: crate::flags::DENSITY_MIN_TOKENS,
            raw_flags: true,
            foreign_any_name: true,
        }
    }
}

/// Whether the system answered or abstained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Passages are returned.
    Answered,
    /// Nothing in the corpus supports an answer.
    NotInCorpus,
}

/// One cited passage. `untrusted` is always true: clause text is data, never instructions.
#[derive(Debug, Clone, Serialize)]
pub struct Passage {
    /// Standard name.
    pub standard: String,
    /// The standard's own version.
    pub std_version: String,
    /// Clause id.
    pub clause_id: String,
    /// Licence tier.
    pub tier: Tier,
    /// sha256 of the stored clause text.
    pub text_sha256: String,
    /// BM25 score for the query terms.
    pub score: f64,
    /// True when the clause was named by id in the query.
    pub exact_id: bool,
    /// OPEN clauses only: the sanitised text, capped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// LICENSED clauses only: one quote of at most 25 words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
    /// True when `text` was cut at the cap.
    pub truncated: bool,
    /// Always true.
    pub untrusted: bool,
    /// Structural flags raised for this clause (see `flags`); empty for ordinary prose.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

/// The result of a search.
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    /// Answered or not in corpus.
    pub verdict: Verdict,
    /// A short code for why (`exact_id`, `bm25`, `below_gate`, `id_not_in_corpus`, `unindexed_standard`, `empty_query`, `unknown_version`).
    pub reason: String,
    /// The corpus version searched.
    pub corpus_version: String,
    /// The corpus hash of that version.
    pub corpus_hash: String,
    /// The passages, best first.
    pub passages: Vec<Passage>,
}

/// The outcome of a cite check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiteVerdict {
    /// The cited hash is the clause's current text hash in that version.
    Ok,
    /// The clause exists in that version but its text hash differs.
    Drift {
        /// The hash the clause has now.
        current_sha256: String,
    },
    /// No such version, standard or clause, or a malformed hash.
    Unknown,
}

/// Why a lookup failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupError(pub String);

struct Doc {
    clause: Clause,
    terms: HashMap<String, u32>,
    /// Tokens of the first words of the clause with the index of the word they came from.
    head: Vec<(usize, String)>,
    len: usize,
    words: usize,
    stops: usize,
    /// Adjacent token pairs (`a b`).
    bigrams: HashSet<String>,
    /// Tokens of the first sentence, and of the rest of the clause, with the word count of the rest.
    first_sentence: HashSet<String>,
    rest: HashSet<String>,
    rest_words: usize,
    /// Content tokens in order, without the query-noise words (for the query-echo test).
    seq: Vec<String>,
    /// Flags from the clause's own statistics and from copies of other clauses.
    flags: Vec<&'static str>,
    /// RS1: flags of the raw text alone (applied only when `Config::raw_flags`).
    raw_flags: Vec<&'static str>,
}

struct Index {
    version: String,
    corpus_hash: String,
    docs: Vec<Doc>,
    df: HashMap<String, usize>,
    /// Median clause length (in indexed tokens) per standard.
    median: HashMap<String, f64>,
    /// The head size the index was built with.
    head_words: usize,
    /// Every adjacent token pair in the corpus.
    all_bigrams: HashSet<String>,
}

/// Flag every clause that contains most of another clause's text (a quoted copy). A parent and its own enhancement are exempt, and so are
/// two clauses of equal text (nothing says which is the original).
fn mark_copies(docs: &mut [Doc]) {
    let sets: Vec<HashSet<u64>> = docs
        .iter()
        .map(|d| crate::flags::shingles(&d.seq))
        .collect();
    let mut post: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, s) in sets.iter().enumerate() {
        for h in s {
            post.entry(*h).or_default().push(i);
        }
    }
    let related = |a: &Doc, b: &Doc| {
        a.clause.standard == b.clause.standard
            && (a.clause.id.starts_with(&b.clause.id) || b.clause.id.starts_with(&a.clause.id))
    };
    let mut copies: Vec<usize> = Vec::new();
    for (a, sa) in sets.iter().enumerate() {
        if sa.len() < 12 {
            continue;
        }
        let mut count: HashMap<usize, usize> = HashMap::new();
        for h in sa {
            if let Some(p) = post.get(h) {
                if p.len() > 50 {
                    continue;
                }
                for b in p {
                    if *b != a {
                        *count.entry(*b).or_default() += 1;
                    }
                }
            }
        }
        for (b, n) in count {
            let larger = sets[b].len() > sa.len();
            if larger
                && (n as f64) >= crate::flags::COPY_SHARE * sa.len() as f64
                && !related(&docs[a], &docs[b])
            {
                copies.push(b);
            }
        }
    }
    for b in copies {
        if !docs[b].flags.contains(&crate::flags::CONTAINS_COPY) {
            docs[b].flags.push(crate::flags::CONTAINS_COPY);
        }
    }
}

/// One query term with its weight.
struct QTerm {
    term: String,
    idf: f64,
    weight: f64,
}

/// A prepared query: weighted terms and adjacent pairs.
struct Query {
    /// The query is written as a question.
    question: bool,
    /// The query's content tokens in order (duplicates kept, noise words and standard names removed).
    seq: Vec<String>,
    terms: Vec<QTerm>,
    bigrams: Vec<(String, f64)>,
}

/// A scored passage candidate.
struct Scored {
    flags: Vec<&'static str>,
    score: f64,
    norm: f64,
    cov: f64,
}

const HEAD_WORDS_INDEXED: usize = 24;

impl Index {
    fn build(version: &str, corpus_hash: &str, mut clauses: Vec<Clause>) -> Index {
        clauses.sort_by(|a, b| (&a.standard, &a.id).cmp(&(&b.standard, &b.id)));
        let mut df: HashMap<String, usize> = HashMap::new();
        let mut docs = Vec::with_capacity(clauses.len());
        let mut toks_all: Vec<Vec<String>> = Vec::with_capacity(clauses.len());
        for c in clauses {
            let mut terms: HashMap<String, u32> = HashMap::new();
            let toks = text::tokens(&c.text);
            for t in &toks {
                *terms.entry(t.clone()).or_default() += 1;
            }
            for t in terms.keys() {
                *df.entry(t.clone()).or_default() += 1;
            }
            let words: Vec<&str> = c.text.split_whitespace().collect();
            let head: Vec<(usize, String)> = words
                .iter()
                .take(HEAD_WORDS_INDEXED)
                .enumerate()
                .flat_map(|(i, w)| text::tokens(w).into_iter().map(move |t| (i, t)))
                .collect();
            let bigrams: HashSet<String> = toks
                .windows(2)
                .map(|w| format!("{} {}", w[0], w[1]))
                .collect();
            let (first, rest_text) = split_first_sentence(&c.text);
            let seq: Vec<String> = toks
                .iter()
                .filter(|t| !NOISE.contains(&t.as_str()))
                .cloned()
                .collect();
            toks_all.push(toks.clone());
            docs.push(Doc {
                seq,
                flags: Vec::new(),
                raw_flags: crate::flags::raw_flags(&c.text),
                first_sentence: text::tokens(first).into_iter().collect(),
                rest: text::tokens(rest_text).into_iter().collect(),
                rest_words: rest_text.split_whitespace().count(),
                bigrams,
                len: toks.len(),
                terms,
                head,
                words: words.len(),
                stops: words.iter().filter(|w| text::is_stop_word(w)).count(),
                clause: c,
            });
        }
        let gdf = crate::flags::gram_df(toks_all.iter().map(Vec::as_slice));
        for (d, toks) in docs.iter_mut().zip(&toks_all) {
            d.flags = crate::flags::static_flags(&d.clause.text, toks, &gdf);
        }
        drop(toks_all);
        mark_copies(&mut docs);
        let all_bigrams: HashSet<String> = docs
            .iter()
            .flat_map(|d| d.bigrams.iter().cloned())
            .collect();
        let mut by_std: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for d in &docs {
            by_std
                .entry(d.clause.standard.as_str())
                .or_default()
                .push(d.len);
        }
        let median = by_std
            .into_iter()
            .map(|(k, mut v)| {
                v.sort_unstable();
                let m = if v.len() % 2 == 1 {
                    v[v.len() / 2] as f64
                } else {
                    (v[v.len() / 2 - 1] + v[v.len() / 2]) as f64 / 2.0
                };
                (k.to_string(), m.max(1.0))
            })
            .collect();
        Index {
            version: version.into(),
            corpus_hash: corpus_hash.into(),
            docs,
            df,
            median,
            head_words: HEAD_WORDS_INDEXED,
            all_bigrams,
        }
    }

    fn idf(&self, df: usize) -> f64 {
        let n = self.docs.len() as f64;
        let df = df as f64;
        (1.0 + (n - df + 0.5) / (df + 0.5)).ln()
    }

    /// Weigh the query terms: a corpus word counts at its idf; a word the corpus does not have counts at `unknown_weight` of the top idf, or
    /// at the full top idf when it looks like a name (unknown acronym, digit-bearing token, mid-sentence capitalised word).
    fn prepare(
        &self,
        terms: &[String],
        entities: &BTreeSet<String>,
        pairs: &[String],
        seq: &[String],
        question: bool,
        cfg: &Config,
    ) -> Query {
        let top = self.idf(0);
        let mut entities = entities.clone();
        let mut unmatched_names = 0usize;
        for p in pairs {
            if !self.all_bigrams.contains(p) {
                entities.extend(p.split(' ').map(String::from));
                unmatched_names += 1;
            }
        }
        let weighted: Vec<QTerm> = terms
            .iter()
            .map(|t| {
                let df = self.df.get(t).copied().unwrap_or(0);
                let idf = self.idf(df);
                let weight = if df > 0 {
                    idf
                } else if cfg.entity_guard && entities.contains(t) {
                    top * cfg.entity_mult
                } else {
                    cfg.unknown_weight * top
                };
                QTerm {
                    term: t.clone(),
                    idf,
                    weight,
                }
            })
            .collect();
        // a capitalised phrase the corpus never contains is a name we do not hold: nothing can match it, so it only adds weight
        let mut weighted = weighted;
        if cfg.entity_guard {
            for i in 0..unmatched_names {
                weighted.push(QTerm {
                    term: format!("\u{0}name{i}"),
                    idf: 0.0,
                    weight: top * cfg.entity_mult,
                });
            }
        }
        let bigrams = weighted
            .windows(2)
            .filter(|w| self.df.contains_key(&w[0].term) && self.df.contains_key(&w[1].term))
            .map(|w| {
                (
                    format!("{} {}", w[0].term, w[1].term),
                    (w[0].idf + w[1].idf) / 2.0,
                )
            })
            .collect();
        Query {
            question,
            seq: seq.to_vec(),
            terms: weighted,
            bigrams,
        }
    }

    fn score(&self, d: &Doc, q: &Query, cfg: &Config) -> Scored {
        let med = self
            .median
            .get(&d.clause.standard)
            .copied()
            .unwrap_or(1.0)
            .max(1.0);
        let len_eff = (d.len as f64).min(cfg.len_cap_mult * med).max(1.0);
        let norm_len = 1.0 - B + B * len_eff / med;
        let head_words = cfg.head_words.min(self.head_words);
        // the head counts only when the clause has a body beyond it
        let has_head = d.words > head_words;
        // a first sentence that echoes the question while the rest of the clause holds none of those words
        let in_first_only =
            |t: &QTerm| d.first_sentence.contains(&t.term) && !d.rest.contains(&t.term);
        let echo = d.rest_words >= 3
            && q.terms.iter().filter(|t| in_first_only(t)).count() >= cfg.echo_terms;
        let (mut sum, mut covered, mut total) = (0.0, 0.0, 0.0);
        for t in &q.terms {
            total += t.weight;
            let body = f64::from(d.terms.get(&t.term).copied().unwrap_or(0).min(cfg.tf_cap));
            if body == 0.0 {
                continue;
            }
            let head_bonus = if has_head
                && d.head
                    .iter()
                    .any(|(i, tok)| *i < head_words && *tok == t.term)
            {
                cfg.head_weight
            } else {
                0.0
            };
            let tf = body + head_bonus;
            covered += t.weight;
            let f = if echo && in_first_only(t) {
                cfg.head_only_factor
            } else {
                1.0
            };
            sum += f * t.idf * tf * (K1 + 1.0) / (tf + K1 * norm_len);
        }
        if cfg.phrase_weight > 0.0 {
            let echo_f = if echo { cfg.head_only_factor } else { 1.0 };
            sum += echo_f
                * cfg.phrase_weight
                * q.bigrams
                    .iter()
                    .filter(|(b, _)| d.bigrams.contains(b))
                    .map(|(_, w)| w)
                    .sum::<f64>();
        }
        let cov = if total > 0.0 { covered / total } else { 0.0 };
        let best = total * (K1 + 1.0);
        let mut norm = if best > 0.0 { sum / best } else { 0.0 };
        let mut score = sum * cov.powf(cfg.cov_exp);
        let prose = d.words < cfg.prose_min_words
            || (d.stops as f64 / d.words.max(1) as f64) >= cfg.prose_stop_ratio;
        if !prose {
            score *= cfg.prose_penalty;
            norm *= cfg.prose_penalty;
        }
        let mut flags: Vec<&'static str> = Vec::new();
        if cfg.structural_flags {
            flags.extend(d.flags.iter().copied());
            if cfg.raw_flags {
                flags.extend(d.raw_flags.iter().copied());
            }
            flags.extend(crate::flags::query_flags_with(
                &q.seq,
                &d.seq,
                q.question,
                cfg.density_min_tokens,
            ));
            if flags.iter().any(|f| crate::flags::excludes(f)) {
                score = 0.0;
                norm = 0.0;
            } else if !flags.is_empty() {
                score *= cfg.flag_factor;
                norm *= cfg.flag_factor;
            }
        }
        Scored {
            flags,
            score,
            norm,
            cov,
        }
    }

    fn standards(&self) -> BTreeSet<&str> {
        self.docs
            .iter()
            .map(|d| d.clause.standard.as_str())
            .collect()
    }
}

fn aliases(standard: &str) -> Vec<String> {
    let mut v: Vec<String> = match standard {
        "NIST-SP-800-53" => vec!["nist sp 800-53", "nist 800-53", "800-53", "nist"],
        "PCI-DSS" => vec!["pci dss", "pci-dss", "pci"],
        "EU-AI-ACT" => vec!["eu ai act", "ai act"],
        "DORA-RTS" => vec!["dora rts", "dora"],
        "HIPAA-SECURITY-RULE" => vec!["hipaa", "45 cfr", "cfr 164"],
        _ => vec![],
    }
    .into_iter()
    .map(String::from)
    .collect();
    v.push(standard.to_lowercase());
    v
}

const NOISE: &[&str] = &[
    "explain",
    "summarize",
    "summarise",
    "summary",
    "quote",
    "say",
    "says",
    "said",
    "require",
    "requires",
    "required",
    "requirement",
    "requirements",
    "clause",
    "clauses",
    "article",
    "articles",
    "control",
    "controls",
    "section",
    "provision",
    "provisions",
    "paragraph",
    "standard",
    "describe",
    "describes",
    "cover",
    "covers",
    "mean",
    "means",
    "tell",
];

/// The id of the clause this one extends: `AU-9(3)` extends `AU-9`, `8.3.10.1` extends `8.3.10`.
fn parent_id(id: &str) -> Option<String> {
    if let Some(i) = id.rfind('(') {
        return (i > 0).then(|| id[..i].to_string());
    }
    id.rfind('.')
        .filter(|i| *i > 0 && id[..*i].contains('.'))
        .map(|i| id[..i].to_string())
}

/// Split a clause after its first sentence (a `.`, `?` or `!` followed by a space), at most 60 words in.
fn split_first_sentence(t: &str) -> (&str, &str) {
    let mut words = 0;
    let b = t.as_bytes();
    for i in 0..b.len() {
        if b[i] == b' ' {
            words += 1;
        }
        if i + 1 < b.len() && matches!(b[i], b'.' | b'?' | b'!') && b[i + 1] == b' ' {
            return (&t[..=i], &t[i + 1..]);
        }
        if words >= 60 {
            break;
        }
    }
    (t, "")
}

const KIND_WORDS: &[&str] = &[
    "article",
    "annex",
    "criterion",
    "criteria",
    "practice",
    "practices",
    "control",
    "controls",
    "requirement",
    "requirements",
    "section",
    "clause",
    "framework",
    "standard",
    "directive",
    "regulation",
    "rule",
    "domain",
    "level",
    "principle",
    "provision",
    "safeguard",
    "baseline",
    "timeline",
    "maturity",
    "benchmark",
    "benchmarks",
    "scheme",
    "programme",
    "program",
    "guideline",
    "guidelines",
    "guidance",
    "matrix",
    "taxonomy",
    "catalogue",
    "catalog",
];

/// Does the query name a standard we do not hold? Structural: an all-capitals or digit-bearing name (not one of the held standards' own
/// name words) followed, after at most two numbers or other acronyms, by a kind word; or an `800-NN` NIST publication number other than 800-53.
fn names_foreign_standard(
    q: &str,
    held_words: &BTreeSet<String>,
    vocab: Option<&HashMap<String, usize>>,
) -> bool {
    let any_name = vocab.is_some();
    if let Some(r) = rx(r"\b800-(\d{2,3})") {
        if r.captures_iter(q).any(|c| &c[1] != "53") {
            return true;
        }
    }
    let words: Vec<&str> = q.split_whitespace().collect();
    let is_name = |w: &str| -> bool {
        let core = w.trim_matches(|c: char| !c.is_alphanumeric());
        // a clause id (AU-9, CP-9) is not the name of a standard
        if rx(r"^[A-Za-z]{1,3}-\d").is_some_and(|r| r.is_match(core)) {
            return false;
        }
        // the words that introduce an id or a kind of provision (ART, ARTICLE, ANNEX, REQUIREMENT ...) are not names, in any case
        let lc = core.to_lowercase();
        if lc == "art" || KIND_WORDS.contains(&lc.as_str()) {
            return false;
        }
        let letters = core.chars().filter(|c| c.is_alphabetic()).count();
        let upper = core.chars().filter(|c| c.is_uppercase()).count();
        let digits = core.chars().filter(|c| c.is_ascii_digit()).count();
        (letters >= 3 && upper == letters)
            || (upper >= 2 && digits >= 1 && letters >= 2)
            || (letters >= 2 && upper >= 2 && core.contains('/'))
    };
    let held = |w: &str| -> bool {
        text::tokens(w.trim_matches(|c: char| !c.is_alphanumeric()))
            .iter()
            .any(|t| held_words.contains(t))
    };
    for (i, w) in words.iter().enumerate() {
        if !is_name(w) || held(w) {
            continue;
        }
        // a roman numeral after an id keyword (Annex VII) is a number
        if i > 0 {
            let prev = words[i - 1]
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase();
            if matches!(
                prev.as_str(),
                "annex" | "annexes" | "appendix" | "schedule" | "chapter" | "title" | "part"
            ) {
                continue;
            }
        }
        if any_name {
            // RS1: a name is foreign only if none of its tokens occurs anywhere in the corpus
            let in_vocab = vocab.is_some_and(|v| {
                text::tokens(w.trim_matches(|c: char| !c.is_alphanumeric()))
                    .iter()
                    .any(|t| v.contains_key(t))
            });
            if in_vocab {
                continue;
            }
            return true;
        }
        let mut skipped = 0;
        for next in words.iter().skip(i + 1) {
            let core = next.trim_matches(|c: char| !c.is_alphanumeric());
            if KIND_WORDS.contains(&core.to_lowercase().as_str()) {
                return true;
            }
            let numberish = !core.is_empty() && core.chars().all(|c| c.is_ascii_digit());
            if (numberish || is_name(next)) && skipped < 2 {
                skipped += 1;
                continue;
            }
            break;
        }
    }
    false
}

/// R3 content-word gate: why the top passage does not support an answer, or `None`. Counts DISTINCT content words only.
fn content_gate(
    terms: &[String],
    doc_terms: &HashMap<String, u32>,
    idx: &Index,
    cfg: &Config,
) -> Option<&'static str> {
    if cfg.content_min_matched == 0 && cfg.content_cov_min <= 0.0 {
        return None;
    }
    let content: Vec<&String> = terms.iter().filter(|t| text::is_content_token(t)).collect();
    if content.is_empty() {
        return None;
    }
    if !content.iter().any(|t| idx.df.contains_key(*t)) {
        return Some("no_content_word");
    }
    let matched = content
        .iter()
        .filter(|t| doc_terms.contains_key(**t))
        .count();
    if matched < cfg.content_min_matched.min(content.len().max(2)) {
        return Some("too_few_content_words");
    }
    if (matched as f64) / (content.len() as f64) < cfg.content_cov_min {
        return Some("low_content_coverage");
    }
    None
}

struct Analysis {
    scope: Option<BTreeSet<String>>,
    candidates: Vec<String>,
    terms: Vec<String>,
    /// The query's content tokens in order (for the echo test).
    seq: Vec<String>,
    /// The query is written as a question.
    question: bool,
    /// Tokens that look like names (unknown acronyms, digit-bearing tokens, mid-sentence capitalised words).
    entities: BTreeSet<String>,
    /// Adjacent capitalised words (`a b`); a pair the corpus never contains marks both words as names.
    entity_pairs: Vec<String>,
    unindexed: bool,
    /// The query names a standard we do not hold.
    foreign: bool,
}

/// Words of the query that look like the name of something: all capitals (3+ letters), letters with digits, long numbers, or a capitalised
/// word that does not start a sentence. Whether the corpus knows them is decided later, from the corpus vocabulary alone.
fn entity_tokens(q: &str) -> (BTreeSet<String>, Vec<String>) {
    let mut out = BTreeSet::new();
    let mut pairs: Vec<String> = Vec::new();
    let mut prev_cap: Option<String> = None;
    let mut sentence_start = true;
    for w in q.split_whitespace() {
        let core: String = w.trim_matches(|c: char| !c.is_alphanumeric()).to_string();
        let letters = core.chars().filter(|c| c.is_alphabetic()).count();
        let digits = core.chars().filter(|c| c.is_ascii_digit()).count();
        let upper = core.chars().filter(|c| c.is_uppercase()).count();
        let all_caps = letters >= 3 && upper == letters && digits == 0;
        let mixed = letters >= 1 && digits >= 1 && core.chars().count() >= 4;
        let long_number = letters == 0 && digits >= 3;
        let capitalised =
            !sentence_start && letters >= 4 && core.chars().next().is_some_and(char::is_uppercase);
        if all_caps || mixed || long_number || capitalised {
            out.extend(text::tokens(&core));
        }
        // a run of capitalised words is a name only if the corpus has the phrase; remember each adjacent pair
        if capitalised {
            let t = text::tokens(&core).join(" ");
            if let Some(p) = &prev_cap {
                pairs.push(format!("{p} {t}"));
            }
            prev_cap = Some(t);
        } else {
            prev_cap = None;
        }
        sentence_start = w.ends_with(['.', '?', '!']);
    }
    (out, pairs)
}

fn rx(p: &str) -> Option<Regex> {
    Regex::new(p).ok()
}

fn analyse(query: &str, idx: &Index, cfg: &Config) -> Analysis {
    let q: String = query.chars().take(MAX_QUERY_CHARS).collect();
    let lower = q.to_lowercase();
    let unindexed = cfg.unindexed_guard
        && rx(r"\b(soc ?2|iso(/iec)?|hitrust|gdpr|cmmc|nis ?2|cnsa|nydfs|23 nycrr|800-171|800-37|800-30|800-61|fedramp|sox|sarbanes|glba|ccpa|cobit|itil|cis controls?|ffiec|fisma)\b")
            .is_some_and(|r| r.is_match(&lower));
    // standard scoping
    let mut scope: BTreeSet<String> = BTreeSet::new();
    let mut alias_tokens: BTreeSet<String> = BTreeSet::new();
    if cfg.scope_by_standard_name {
        for std in idx.standards() {
            for a in aliases(std) {
                let found = rx(&format!(r"(^|[^a-z0-9]){}([^a-z0-9]|$)", regex::escape(&a)))
                    .is_some_and(|r| r.is_match(&lower));
                if found {
                    scope.insert(std.to_string());
                    alias_tokens.extend(text::tokens(&a));
                }
            }
        }
    }
    let held_words: BTreeSet<String> = idx
        .standards()
        .into_iter()
        .flat_map(aliases)
        .flat_map(|a| text::tokens(&a))
        .collect();
    // id candidates; each pattern's span is blanked so the dotted pattern cannot re-read part of an already matched id
    let mut work = q.clone();
    // a version mention ("v4.0.1", "Rev 5.2.0", "version 2.0") is not a clause id
    if let Some(v) = rx(r"(?i)\b(?:v|rev\.?|version)\s*\d{1,2}(?:\.\d{1,2}){1,3}") {
        work = v
            .replace_all(&work, |c: &regex::Captures| " ".repeat(c[0].len()))
            .into_owned();
    }
    let mut cands: Vec<(usize, String)> = Vec::new();
    let mut take =
        |pattern: &str, build: &dyn Fn(&regex::Captures) -> Option<String>, work: &mut String| {
            let Some(r) = rx(pattern) else { return };
            let snapshot = work.clone();
            for c in r.captures_iter(&snapshot) {
                if let (Some(m), Some(id)) = (c.get(0), build(&c)) {
                    cands.push((m.start(), id));
                    work.replace_range(m.start()..m.end(), &" ".repeat(m.end() - m.start()));
                }
            }
        };
    // HIPAA: any section 164.NNN with any run of parenthesised subsection labels, written as in the regulation: 164.312(a)(2)(iv)
    take(
        r"(?i)\b164\.(\d+)((?:\s*\(\s*[a-z0-9]{1,4}\s*\))*)",
        &|c| {
            let groups: String = c[2].chars().filter(|ch| !ch.is_whitespace()).collect();
            Some(format!("164.{}{}", &c[1], groups))
        },
        &mut work,
    );
    // NIST: family-number, with an enhancement written (n), ( n ) or .n, and any run of lettered or numbered parts after it; every digit run is
    // taken whole, so a longer number (SR-100) is never read as its held prefix (SR-10)
    take(
        r"(?i)\b([a-z]{1,2})-(\d+)(?:\s*(?:\(\s*(\d+)\s*\)|\.(\d+)))?((?:\s*\(\s*[a-z0-9]{1,4}\s*\))*)",
        &|c| {
            let base = format!("{}-{}", c[1].to_uppercase(), &c[2]);
            let mut id = match c.get(3).or(c.get(4)) {
                Some(e) => format!("{base}({})", e.as_str()),
                None => base,
            };
            if let Some(parts) = c.get(5) {
                id.push_str(
                    &parts
                        .as_str()
                        .chars()
                        .filter(|ch| !ch.is_whitespace())
                        .collect::<String>(),
                );
            }
            Some(id)
        },
        &mut work,
    );
    take(
        r"(?i)\b(?:article|art)\.?\s*(\d+)\b",
        &|c| Some(format!("Art.{}", &c[1])),
        &mut work,
    );
    take(
        r"(?i)\bannex\s+([ivxlc]{1,12}|\d+)\b",
        &|c| Some(format!("Annex {}", c[1].to_uppercase())),
        &mut work,
    );
    // another scheme's code written with a letter prefix (A.5.1, CC6.1, A1.1.1): id-shaped, resolved like any other, so it abstains here
    take(
        r"(?i)\b([a-z]{1,3})\.?(\d+(?:\.\d+)+)\b",
        &|c| Some(c[0].to_uppercase()),
        &mut work,
    );
    // dotted numbers (PCI): not inside another dotted code, and not a product or protocol version (TLS 1.2: the word before is an unknown acronym)
    {
        let held_for_ids: &BTreeSet<String> = &held_words;
        take(
            r"(?:^|[^A-Za-z0-9.\-])(\d+(?:\.\d+)+)\b",
            &|c| {
                let m = c.get(1)?;
                let first: u32 = m
                    .as_str()
                    .split('.')
                    .next()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(0);
                if !(1..=99).contains(&first) {
                    return None;
                }
                let before = q[..m.start()].trim_end();
                let prev: String = before
                    .rsplit(char::is_whitespace)
                    .next()
                    .unwrap_or("")
                    .trim_matches(|ch: char| !ch.is_alphanumeric())
                    .to_string();
                let acronym = prev.chars().count() >= 2
                    && prev
                        .chars()
                        .all(|ch| ch.is_alphabetic() && ch.is_uppercase());
                let held = text::tokens(&prev).iter().any(|t| held_for_ids.contains(t));
                let kind = KIND_WORDS.contains(&prev.to_lowercase().as_str());
                if acronym && !held && !kind {
                    return None;
                }
                Some(m.as_str().to_string())
            },
            &mut work,
        );
    }
    cands.sort();
    let mut candidates: Vec<String> = Vec::new();
    for (_, id) in cands {
        if !candidates.contains(&id) {
            candidates.push(id);
        }
    }
    // text terms
    let mut terms: Vec<String> = Vec::new();
    for t in text::tokens(&q) {
        if !alias_tokens.contains(&t) && !NOISE.contains(&t.as_str()) && !terms.contains(&t) {
            terms.push(t);
        }
        if terms.len() >= MAX_TERMS {
            break;
        }
    }
    let seq: Vec<String> = text::tokens(&q)
        .into_iter()
        .filter(|t| !alias_tokens.contains(t) && !NOISE.contains(&t.as_str()))
        .collect();
    let (ent, entity_pairs) = entity_tokens(&q);
    let entities = ent
        .into_iter()
        .filter(|t| !alias_tokens.contains(t))
        .collect();
    let foreign = cfg.foreign_guard
        && names_foreign_standard(&q, &held_words, cfg.foreign_any_name.then_some(&idx.df));
    Analysis {
        foreign,
        scope: (!scope.is_empty()).then_some(scope),
        candidates,
        terms,
        seq,
        question: crate::flags::is_question(&q),
        entities,
        entity_pairs,
        unindexed,
    }
}

fn passage(d: &Doc, score: f64, exact: bool, terms: &[String], flags: &[&'static str]) -> Passage {
    let clean = text::sanitise(&d.clause.text);
    let (text_out, quote, truncated) = match d.clause.tier {
        Tier::Open => {
            let truncated = clean.chars().count() > TEXT_CAP;
            (
                Some(clean.chars().take(TEXT_CAP).collect::<String>()),
                None,
                truncated,
            )
        }
        Tier::Licensed => (
            None,
            Some(if terms.is_empty() {
                text::first_words(&clean, QUOTE_WORDS)
            } else {
                text::best_window(&clean, terms, QUOTE_WORDS)
            }),
            false,
        ),
    };
    Passage {
        standard: d.clause.standard.clone(),
        std_version: d.clause.std_version.clone(),
        clause_id: d.clause.id.clone(),
        tier: d.clause.tier,
        text_sha256: d.clause.text_sha256.clone(),
        score,
        exact_id: exact,
        text: text_out,
        quote,
        truncated,
        untrusted: true,
        flags: flags.iter().map(|f| (*f).to_string()).collect(),
    }
}

/// The retriever: one or more sealed corpus versions held in memory.
pub struct Retriever {
    indexes: BTreeMap<String, Index>,
}

impl Retriever {
    /// A retriever over one version built from clauses.
    pub fn from_clauses(version: &str, corpus_hash: &str, clauses: Vec<Clause>) -> Retriever {
        let mut r = Retriever {
            indexes: BTreeMap::new(),
        };
        r.add_clauses(version, corpus_hash, clauses);
        r
    }
    /// A retriever over several sealed (and re-verified) versions.
    pub fn from_sealed(versions: Vec<Sealed>) -> Retriever {
        let mut r = Retriever {
            indexes: BTreeMap::new(),
        };
        for s in versions {
            r.add_clauses(
                &s.manifest.corpus_version,
                &s.manifest.corpus_hash,
                s.clauses,
            );
        }
        r
    }
    /// Add one more version.
    pub fn add_clauses(&mut self, version: &str, corpus_hash: &str, clauses: Vec<Clause>) {
        self.indexes
            .insert(version.into(), Index::build(version, corpus_hash, clauses));
    }
    /// Diagnostic: every clause's score, normalised score, coverage and flags for a query, best first (before any gate; ids only).
    pub fn explain(&self, query: &str, version: Option<&str>, cfg: &Config) -> Vec<String> {
        let Some(idx) = self.pick(version) else {
            return vec![];
        };
        let a = analyse(query, idx, cfg);
        let q = idx.prepare(
            &a.terms,
            &a.entities,
            &a.entity_pairs,
            &a.seq,
            a.question,
            cfg,
        );
        let mut rows: Vec<(f64, String)> = idx
            .docs
            .iter()
            .map(|d| {
                let sc = idx.score(d, &q, cfg);
                (
                    sc.score,
                    format!(
                        "{} score={:.3} norm={:.3} cov={:.2} flags={:?}",
                        d.clause.id, sc.score, sc.norm, sc.cov, sc.flags
                    ),
                )
            })
            .collect();
        rows.sort_by(|x, y| y.0.total_cmp(&x.0));
        rows.into_iter().map(|r| r.1).take(8).collect()
    }

    /// Diagnostic: the structural flags of every flagged clause in a version, by standard and id (never text).
    pub fn flag_census(&self, version: Option<&str>) -> Vec<(String, String, Vec<String>)> {
        self.pick(version)
            .map(|i| {
                i.docs
                    .iter()
                    .filter(|d| !d.flags.is_empty())
                    .map(|d| {
                        (
                            d.clause.standard.clone(),
                            d.clause.id.clone(),
                            d.flags.iter().map(|f| (*f).to_string()).collect(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The loaded versions, sorted.
    pub fn versions(&self) -> Vec<String> {
        self.indexes.keys().cloned().collect()
    }

    /// The loaded versions with their corpus hashes, sorted by version name.
    pub fn version_info(&self) -> Vec<(String, String)> {
        self.indexes
            .values()
            .map(|i| (i.version.clone(), i.corpus_hash.clone()))
            .collect()
    }

    fn pick(&self, version: Option<&str>) -> Option<&Index> {
        match version {
            Some(v) => self.indexes.get(v),
            None => self.indexes.values().next_back(),
        }
    }

    /// Search. `version` pins the corpus version (default: the newest). `k` is clamped to 1..=10.
    pub fn search(
        &self,
        query: &str,
        version: Option<&str>,
        k: usize,
        cfg: &Config,
    ) -> SearchResult {
        let k = k.clamp(1, MAX_K);
        let Some(idx) = self.pick(version) else {
            return SearchResult {
                verdict: Verdict::NotInCorpus,
                reason: "unknown_version".into(),
                corpus_version: version.unwrap_or("").into(),
                corpus_hash: String::new(),
                passages: vec![],
            };
        };
        let done = |verdict, reason: &str, passages| SearchResult {
            verdict,
            reason: reason.into(),
            corpus_version: idx.version.clone(),
            corpus_hash: idx.corpus_hash.clone(),
            passages,
        };
        let a = analyse(query, idx, cfg);
        if a.unindexed {
            return done(Verdict::NotInCorpus, "unindexed_standard", vec![]);
        }
        if a.foreign {
            return done(Verdict::NotInCorpus, "other_standard", vec![]);
        }
        let in_scope = |d: &Doc| {
            a.scope
                .as_ref()
                .is_none_or(|s| s.contains(&d.clause.standard))
        };
        if !a.candidates.is_empty() {
            let mut hits: Vec<&Doc> = Vec::new();
            for id in &a.candidates {
                let mut found: Vec<&Doc> = idx
                    .docs
                    .iter()
                    .filter(|d| in_scope(d) && d.clause.id.eq_ignore_ascii_case(id))
                    .collect();
                if found.is_empty() && !id.contains('(') {
                    // a held section named without its subsections (164.312) gives those subsections
                    let pre = format!("{}(", id.to_lowercase());
                    found = idx
                        .docs
                        .iter()
                        .filter(|d| in_scope(d) && d.clause.id.to_lowercase().starts_with(&pre))
                        .collect();
                }
                if found.is_empty() {
                    // a version of a standard written after its name (PCI DSS 4.0, 4.0.1) is not a clause id
                    if rx(r"^\d{1,2}\.0(?:\.\d{1,2})?$").is_some_and(|r| r.is_match(id)) {
                        continue;
                    }
                    return done(Verdict::NotInCorpus, "id_not_in_corpus", vec![]);
                }
                for d in found {
                    if !hits.iter().any(|h| std::ptr::eq(*h, d)) {
                        hits.push(d);
                    }
                }
            }
            if !hits.is_empty() {
                let q = idx.prepare(
                    &a.terms,
                    &a.entities,
                    &a.entity_pairs,
                    &a.seq,
                    a.question,
                    cfg,
                );
                let passages = hits
                    .into_iter()
                    .take(k)
                    .map(|d| {
                        let fl: Vec<&'static str> = if cfg.structural_flags {
                            d.flags.clone()
                        } else {
                            vec![]
                        };
                        passage(d, idx.score(d, &q, cfg).score, true, &a.terms, &fl)
                    })
                    .collect();
                return done(Verdict::Answered, "exact_id", passages);
            }
        }
        if a.terms.is_empty() {
            return done(Verdict::NotInCorpus, "empty_query", vec![]);
        }
        let q = idx.prepare(
            &a.terms,
            &a.entities,
            &a.entity_pairs,
            &a.seq,
            a.question,
            cfg,
        );
        let mut scored: Vec<(Scored, &Doc)> = idx
            .docs
            .iter()
            .filter(|d| in_scope(d))
            .map(|d| (idx.score(d, &q, cfg), d))
            .filter(|(s, _)| s.score > 0.0)
            .collect();
        scored.sort_by(|x, y| {
            y.0.score.total_cmp(&x.0.score).then_with(|| {
                (&x.1.clause.standard, &x.1.clause.id).cmp(&(&y.1.clause.standard, &y.1.clause.id))
            })
        });
        if cfg.parent_ratio > 0.0 {
            if let Some(top_id) = scored.first().map(|(_, d)| d.clause.id.clone()) {
                let std = scored[0].1.clause.standard.clone();
                if let Some(parent) = parent_id(&top_id) {
                    let top_score = scored[0].0.score;
                    if let Some(pos) = scored.iter().position(|(sc, d)| {
                        d.clause.standard == std
                            && d.clause.id == parent
                            && sc.score >= cfg.parent_ratio * top_score
                    }) {
                        let item = scored.remove(pos);
                        scored.insert(0, item);
                    }
                }
            }
        }
        let Some(first) = scored.first() else {
            return done(Verdict::NotInCorpus, "below_gate", vec![]);
        };
        if first.0.score < cfg.score_floor
            || first.0.cov < cfg.coverage_min
            || first.0.norm < cfg.min_norm_score
        {
            return done(Verdict::NotInCorpus, "below_gate", vec![]);
        }
        if let Some(why) = content_gate(&a.terms, &first.1.terms, idx, cfg) {
            return done(Verdict::NotInCorpus, why, vec![]);
        }
        done(
            Verdict::Answered,
            "bm25",
            scored
                .into_iter()
                .take(k)
                .map(|(s, d)| passage(d, s.score, false, &a.terms, &s.flags))
                .collect(),
        )
    }

    /// One clause by standard and id (case-insensitive id), in a pinned version. A LICENSED clause returns its quote only.
    pub fn lookup_clause(
        &self,
        standard: &str,
        clause: &str,
        version: Option<&str>,
        query_hint: Option<&str>,
    ) -> Result<Passage, LookupError> {
        let idx = self
            .pick(version)
            .ok_or_else(|| LookupError("unknown corpus version".into()))?;
        let d = idx
            .docs
            .iter()
            .find(|d| d.clause.standard == standard && d.clause.id.eq_ignore_ascii_case(clause))
            .ok_or_else(|| LookupError("no such clause in that version".into()))?;
        let terms = query_hint.map(text::tokens).unwrap_or_default();
        let q = idx.prepare(
            &terms,
            &BTreeSet::new(),
            &[],
            &[],
            false,
            &Config::default(),
        );
        Ok(passage(
            d,
            idx.score(d, &q, &Config::default()).score,
            true,
            &terms,
            &d.flags,
        ))
    }

    /// Is `hash` the current text hash of the clause in that version?
    pub fn cite_check(
        &self,
        standard: &str,
        clause: &str,
        version: &str,
        hash: &str,
    ) -> CiteVerdict {
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return CiteVerdict::Unknown;
        }
        let Some(idx) = self.indexes.get(version) else {
            return CiteVerdict::Unknown;
        };
        match idx
            .docs
            .iter()
            .find(|d| d.clause.standard == standard && d.clause.id.eq_ignore_ascii_case(clause))
        {
            None => CiteVerdict::Unknown,
            Some(d) if d.clause.text_sha256.eq_ignore_ascii_case(hash) => CiteVerdict::Ok,
            Some(d) => CiteVerdict::Drift {
                current_sha256: d.clause.text_sha256.clone(),
            },
        }
    }
}
