//! R3 structural injection defences. Nothing here knows an attack family: a clause is flagged from its own statistics (how few distinct terms
//! make up its length, whether one phrase repeats, whether it carries look-alike characters, whether it contains a copy of another clause) or
//! from how it relates to the query (it repeats the query's content words in the query's own order, or its words are mostly query words).
//! A flagged clause is demoted (score times `Config::flag_factor`) or, for look-alike characters, excluded; the response carries the flag.

use std::collections::{HashMap, HashSet};

/// A clause with look-alike (confusable) letters: excluded from text search.
pub const CONFUSABLE: &str = "confusable_chars";
/// A long clause made of few distinct terms.
pub const LOW_DIVERSITY: &str = "low_diversity";
/// A clause in which every distinct term occurs about equally often and more than once (a block of terms repeated).
pub const UNIFORM_TERMS: &str = "uniform_terms";
/// A three-term phrase that repeats many times.
pub const REPEATED_PHRASE: &str = "repeated_phrase";
/// A clause that contains most of another clause's text.
pub const CONTAINS_COPY: &str = "contains_copy";
/// A clause that repeats the query's content words in the query's own order.
pub const QUERY_ECHO: &str = "query_echo";
/// A clause in which query words are a large share of all its words.
pub const DENSE_KEYWORDS: &str = "dense_keywords";

/// Smallest number of content tokens for the diversity and repetition tests (shorter clauses are never judged).
pub const MIN_TOKENS: usize = 12;
/// Distinct-to-total ratio under which a clause of at least `MIN_TOKENS * 4/3` tokens is flagged for low diversity.
pub const DIVERSITY_MIN: f64 = 0.3;
/// A three-term phrase that occurs this many times flags the clause, provided its occurrences cover at least `PHRASE_COVER` of the clause.
pub const PHRASE_REPEATS: usize = 4;
/// See [`PHRASE_REPEATS`]: the share of the clause's tokens that the repeats of its most repeated three-term phrase span.
pub const PHRASE_COVER: f64 = 0.2;
/// Share of another clause's 5-term shingles that a clause must contain to be flagged as a copy.
pub const COPY_SHARE: f64 = 0.9;
/// Shortest run of query terms (content tokens, in order) that makes a clause an echo, and the share of the query it must cover.
pub const ECHO_RUN: usize = 5;
/// See [`ECHO_RUN`].
pub const ECHO_SHARE: f64 = 0.85;
/// Share of a clause's tokens that are query terms above which it is flagged as dense, when it has at least `DENSITY_MIN_TOKENS` tokens.
pub const DENSITY_MAX: f64 = 0.6;
/// Fewest tokens a clause needs before its query density is judged.
pub const DENSITY_MIN_TOKENS: usize = 24;

/// Flags that exclude a clause from text search (the others demote it).
pub fn excludes(flag: &str) -> bool {
    flag == CONFUSABLE
}

/// A three-term phrase that occurs in this many clauses of the corpus is boilerplate of the standard, not stuffing.
pub const BOILERPLATE_DF: u32 = 8;

/// How many clauses of the corpus contain each three-term phrase (see [`BOILERPLATE_DF`]).
pub type GramDf = HashMap<(String, String, String), u32>;

/// Count, for each three-term phrase, the clauses that contain it.
pub fn gram_df<'a>(docs: impl Iterator<Item = &'a [String]>) -> GramDf {
    let mut df: GramDf = HashMap::new();
    for toks in docs {
        let set: HashSet<(String, String, String)> = toks
            .windows(3)
            .map(|w| (w[0].clone(), w[1].clone(), w[2].clone()))
            .collect();
        for g in set {
            *df.entry(g).or_default() += 1;
        }
    }
    df
}

/// Statistics-only flags of a clause, from its raw text and its content tokens. `df` says which phrases are corpus boilerplate.
pub fn static_flags(raw: &str, toks: &[String], df: &GramDf) -> Vec<&'static str> {
    let mut f = Vec::new();
    if raw.chars().any(crate::text::is_confusable) {
        f.push(CONFUSABLE);
    }
    let n = toks.len();
    if n >= MIN_TOKENS * 4 / 3 {
        let distinct: HashSet<&String> = toks.iter().collect();
        if (distinct.len() as f64) / (n as f64) < DIVERSITY_MIN {
            f.push(LOW_DIVERSITY);
        }
    }
    if n >= MIN_TOKENS {
        let mut counts: HashMap<&String, usize> = HashMap::new();
        for t in toks {
            *counts.entry(t).or_default() += 1;
        }
        let (lo, hi) = (
            counts.values().copied().min().unwrap_or(0),
            counts.values().copied().max().unwrap_or(0),
        );
        if counts.len() >= 3 && lo >= 2 && hi <= lo + 1 {
            f.push(UNIFORM_TERMS);
        }
        let mut grams: HashMap<(String, String, String), usize> = HashMap::new();
        for w in toks.windows(3) {
            *grams
                .entry((w[0].clone(), w[1].clone(), w[2].clone()))
                .or_default() += 1;
        }
        let top = grams
            .iter()
            .filter(|(g, _)| df.get(*g).copied().unwrap_or(0) < BOILERPLATE_DF)
            .map(|(_, c)| *c)
            .max()
            .unwrap_or(0);
        if top >= PHRASE_REPEATS && (top * 3) as f64 / n as f64 >= PHRASE_COVER {
            f.push(REPEATED_PHRASE);
        }
    }
    f
}

/// Hashes of every run of five consecutive tokens.
pub fn shingles(toks: &[String]) -> HashSet<u64> {
    toks.windows(5)
        .map(|w| {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            w.hash(&mut h);
            h.finish()
        })
        .collect()
}

/// Length of the longest run of consecutive query tokens that also appears consecutively in the clause.
pub fn longest_run(query: &[String], doc: &[String]) -> usize {
    let mut best = 0;
    let mut prev = vec![0usize; doc.len() + 1];
    for q in query {
        let mut cur = vec![0usize; doc.len() + 1];
        for (j, d) in doc.iter().enumerate() {
            if q == d {
                cur[j + 1] = prev[j] + 1;
                best = best.max(cur[j + 1]);
            }
        }
        prev = cur;
    }
    best
}

/// Is the query written as a question (a question mark, or an interrogative word)? A statement that quotes a phrase of a clause is a lookup of
/// that phrase, not a mirror of a question, so the echo test is applied to questions only (a documented limit: a statement-style query can be
/// mirrored).
pub fn is_question(raw: &str) -> bool {
    raw.contains('?')
        || raw
            .to_lowercase()
            .split(|c: char| !c.is_alphabetic())
            .any(|w| {
                matches!(
                    w,
                    "how" | "what" | "which" | "who" | "whom" | "whose" | "when" | "where" | "why"
                )
            })
}

/// Query-relative flags: the clause echoes the query (a question), or its words are mostly query words.
pub fn query_flags(query_seq: &[String], doc_seq: &[String], question: bool) -> Vec<&'static str> {
    let mut f = Vec::new();
    if question && query_seq.len() >= ECHO_RUN {
        let run = longest_run(query_seq, doc_seq);
        if run >= ECHO_RUN && (run as f64) >= ECHO_SHARE * query_seq.len() as f64 {
            f.push(QUERY_ECHO);
        }
    }
    if doc_seq.len() >= DENSITY_MIN_TOKENS {
        let q: HashSet<&String> = query_seq.iter().collect();
        let hits = doc_seq.iter().filter(|t| q.contains(t)).count();
        if (hits as f64) / (doc_seq.len() as f64) > DENSITY_MAX {
            f.push(DENSE_KEYWORDS);
        }
    }
    f
}
