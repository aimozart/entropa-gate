//! R2 evaluation: our DEV sets and the sealed held-out runner. The held-out file's sha256 is checked BEFORE it is parsed; the report
//! carries counts, 95 percent bounds and ids only, never question text. Injection and stale cases build a tiny corpus each through the same
//! retriever the real corpus uses.

use crate::corpus::{text_sha256, Clause, Tier};
use crate::eval::upper95;
use crate::retrieve::{Config, Retriever, Verdict};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The sha256 of the sealed held-out file (from the R2 order). The runner refuses any other file.
pub const HELDOUT_SHA256: &str = "d7b2837960333c968a2cf1d6f771da1b2d4820802cb8bacc4a229d45835e525a";

/// A description-only or id-named question.
#[derive(Debug, Clone)]
pub struct DescQ {
    /// Label (`dd-NN` in DEV, `pos-NN` in the held-out set).
    pub label: String,
    /// The question.
    pub query: String,
    /// Expected `STANDARD:ID`.
    pub expected: String,
}

/// An out-of-corpus question.
#[derive(Debug, Clone)]
pub struct OocQ {
    /// Label.
    pub label: String,
    /// The question.
    pub query: String,
}

/// An injection case with its own tiny corpus.
#[derive(Debug, Clone)]
pub struct InjCase {
    /// Case id.
    pub label: String,
    /// Attack family.
    pub family: String,
    /// (standard, id, text) of each clause (tier OPEN).
    pub clauses: Vec<(String, String, String)>,
    /// The query.
    pub query: String,
    /// Expected top-1 `STANDARD:ID`.
    pub expected: String,
}

/// A stale-version case.
#[derive(Debug, Clone)]
pub struct StaleCase {
    /// Case id.
    pub label: String,
    /// Standard name.
    pub standard: String,
    /// Clause id.
    pub clause: String,
    /// Text under version `v1`.
    pub v1: String,
    /// Text under version `v2`.
    pub v2: String,
    /// The query.
    pub query: String,
    /// `v1` or `v2`.
    pub pinned: String,
    /// sha256 of the text that must be returned.
    pub expected_sha: String,
}

/// The DEV sets.
#[derive(Debug, Clone)]
pub struct DevSets {
    /// Description-only questions.
    pub desc: Vec<DescQ>,
    /// Out-of-corpus questions.
    pub ooc: Vec<OocQ>,
    /// Injection cases.
    pub inj: Vec<InjCase>,
    /// The second out-of-corpus DEV set (common standard names), added after the R1 regression run; empty if absent.
    pub ooc2: Vec<OocQ>,
}

/// The held-out sets.
#[derive(Debug, Clone)]
pub struct HeldOut {
    /// Description-only questions.
    pub desc: Vec<DescQ>,
    /// Id-named questions.
    pub idn: Vec<DescQ>,
    /// Out-of-corpus questions.
    pub ooc: Vec<OocQ>,
    /// Injection cases.
    pub inj: Vec<InjCase>,
    /// Stale-version cases.
    pub stale: Vec<StaleCase>,
}

pub(crate) fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub(crate) fn s(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| format!("missing field {k}"))
}

pub(crate) fn jsonl(p: &Path) -> Result<Vec<Value>, String> {
    std::fs::read_to_string(p)
        .map_err(|_| format!("cannot read {}", p.display()))?
        .lines()
        .map(|l| serde_json::from_str(l).map_err(|_| "bad json line".to_string()))
        .collect()
}

pub(crate) fn inj_case(v: &Value, idk: &str) -> Result<InjCase, String> {
    let clauses = v["clauses"]
        .as_array()
        .ok_or("no clauses")?
        .iter()
        .map(|c| Ok((s(c, "standard")?, s(c, "id")?, s(c, "text")?)))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(InjCase {
        label: s(v, idk)?,
        family: s(v, "family")?,
        clauses,
        query: s(v, "query")?,
        expected: s(v, "expected")?,
    })
}

/// Load the DEV sets after verifying `DEV_FROZEN.json`.
pub fn load_dev(dir: &Path) -> Result<DevSets, String> {
    let frozen: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("DEV_FROZEN.json"))
            .map_err(|_| "no DEV_FROZEN.json".to_string())?,
    )
    .map_err(|_| "bad DEV_FROZEN.json".to_string())?;
    for (name, h) in frozen["files"].as_object().ok_or("no files")? {
        let b = std::fs::read(dir.join(name)).map_err(|_| format!("cannot read {name}"))?;
        if Some(sha_hex(&b).as_str()) != h.as_str() {
            return Err(format!("DEV file {name} does not match its frozen hash"));
        }
    }
    let desc = jsonl(&dir.join("dev_description.jsonl"))?
        .iter()
        .map(|v| {
            Ok(DescQ {
                label: s(v, "qid")?,
                query: s(v, "query")?,
                expected: format!("{}:{}", s(v, "standard")?, s(v, "expected")?),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let ooc = jsonl(&dir.join("dev_out_of_corpus.jsonl"))?
        .iter()
        .map(|v| {
            Ok(OocQ {
                label: s(v, "qid")?,
                query: s(v, "query")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let inj = jsonl(&dir.join("dev_injection.jsonl"))?
        .iter()
        .map(|v| inj_case(v, "case"))
        .collect::<Result<Vec<_>, String>>()?;
    let mut ooc2 = Vec::new();
    if dir.join("DEV2_FROZEN.json").exists() {
        let f2: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("DEV2_FROZEN.json"))
                .map_err(|_| "no DEV2_FROZEN.json".to_string())?,
        )
        .map_err(|_| "bad DEV2_FROZEN.json".to_string())?;
        for (name, h) in f2["files"].as_object().ok_or("no files")? {
            let b = std::fs::read(dir.join(name)).map_err(|_| format!("cannot read {name}"))?;
            if Some(sha_hex(&b).as_str()) != h.as_str() {
                return Err(format!("DEV file {name} does not match its frozen hash"));
            }
        }
        ooc2 = jsonl(&dir.join("dev_out_of_corpus_2.jsonl"))?
            .iter()
            .map(|v| {
                Ok(OocQ {
                    label: s(v, "qid")?,
                    query: s(v, "query")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
    }
    Ok(DevSets {
        desc,
        ooc,
        inj,
        ooc2,
    })
}

/// Load the sealed held-out file. The sha256 is checked first; on a mismatch nothing is parsed and the error names no content.
pub fn load_heldout(path: &Path, expected_sha: &str) -> Result<HeldOut, String> {
    let bytes = std::fs::read(path).map_err(|_| "cannot read the sealed file".to_string())?;
    if !sha_hex(&bytes).eq_ignore_ascii_case(expected_sha) {
        return Err("the sealed file does not match its sha256: refused".into());
    }
    let v: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "the sealed file is not valid json".to_string())?;
    let list = |k: &str| v[k].as_array().cloned().unwrap_or_default();
    let dq = |k: &str| -> Result<Vec<DescQ>, String> {
        list(k)
            .iter()
            .enumerate()
            .map(|(i, x)| {
                Ok(DescQ {
                    label: format!("{k}-{:02}", i + 1),
                    query: s(x, "q")?,
                    expected: s(x, "expected")?,
                })
            })
            .collect()
    };
    Ok(HeldOut {
        desc: dq("description_only")?,
        idn: dq("id_named")?,
        ooc: list("out_of_corpus")
            .iter()
            .enumerate()
            .map(|(i, x)| {
                Ok(OocQ {
                    label: format!("out_of_corpus-{:02}", i + 1),
                    query: s(x, "q")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        inj: list("injection")
            .iter()
            .map(|x| inj_case(x, "case"))
            .collect::<Result<Vec<_>, String>>()?,
        stale: list("stale_version")
            .iter()
            .map(|x| {
                Ok(StaleCase {
                    label: s(x, "case")?,
                    standard: s(x, "standard")?,
                    clause: s(x, "clause")?,
                    v1: s(x, "version_1_text")?,
                    v2: s(x, "version_2_text")?,
                    query: s(x, "query")?,
                    pinned: s(x, "pinned_version")?,
                    expected_sha: s(x, "expected_text_sha256")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}

pub(crate) fn open_clause(std: &str, ver: &str, id: &str, text: &str) -> Clause {
    Clause {
        standard: std.into(),
        std_version: ver.into(),
        id: id.into(),
        tier: Tier::Open,
        text: text.into(),
        text_sha256: text_sha256(text),
    }
}

/// The outcome of one injection case.
#[derive(Debug, Clone)]
pub struct InjOutcome {
    /// True if the top-1 passage is not the expected clause or a passage is not marked untrusted.
    pub obeyed: bool,
    /// What came back (`STANDARD:ID` or `abstain:<reason>`).
    pub got: String,
    /// Every returned passage as `ID[flags]`, best first (ids and flag names only).
    pub ranked: Vec<String>,
}

/// Run one injection case against its own tiny corpus.
pub fn score_injection(case: &InjCase, cfg: &Config) -> InjOutcome {
    let clauses = case
        .clauses
        .iter()
        .map(|(st, id, t)| open_clause(st, "1", id, t))
        .collect();
    let r = Retriever::from_clauses("syn", &"1".repeat(64), clauses);
    let res = r.search(&case.query, Some("syn"), 5, cfg);
    let got = match (res.verdict, res.passages.first()) {
        (Verdict::Answered, Some(p)) => format!("{}:{}", p.standard, p.clause_id),
        _ => format!("abstain:{}", res.reason),
    };
    let untrusted = res.passages.iter().all(|p| p.untrusted);
    let ranked = res
        .passages
        .iter()
        .map(|p| format!("{}[{}]", p.clause_id, p.flags.join(",")))
        .collect();
    InjOutcome {
        obeyed: got != case.expected || !untrusted,
        got,
        ranked,
    }
}

/// Run one stale-version case: two versions of a one-clause standard, a pinned query, and the sha256 of the returned text.
pub fn score_stale(case: &StaleCase, cfg: &Config) -> bool {
    let mut r = Retriever::from_clauses(
        "v1",
        &"3".repeat(64),
        vec![open_clause(&case.standard, "1", &case.clause, &case.v1)],
    );
    r.add_clauses(
        "v2",
        &"4".repeat(64),
        vec![open_clause(&case.standard, "2", &case.clause, &case.v2)],
    );
    let res = r.search(&case.query, Some(&case.pinned), 3, cfg);
    res.passages
        .first()
        .is_some_and(|p| p.text_sha256.eq_ignore_ascii_case(&case.expected_sha))
}

pub(crate) fn got_of(r: &crate::retrieve::SearchResult) -> String {
    match (r.verdict, r.passages.first()) {
        (Verdict::Answered, Some(p)) => format!("{}:{}", p.standard, p.clause_id),
        _ => format!("abstain:{}", r.reason),
    }
}

pub(crate) fn tally(correct: usize, n: usize) -> Value {
    json!({"n": n, "correct": correct, "accuracy": if n == 0 { 0.0 } else { correct as f64 / n as f64 },
           "upper95_of_failure_rate": upper95((n - correct) as u64, n as u64)})
}

pub(crate) fn desc_block(real: &Retriever, ver: &str, qs: &[DescQ], cfg: &Config) -> Value {
    let mut ok = 0;
    let mut misses = vec![];
    for q in qs {
        let got = got_of(&real.search(&q.query, Some(ver), 5, cfg));
        if got == q.expected {
            ok += 1;
        } else {
            misses.push(json!({"id": q.label, "expected": q.expected, "got": got}));
        }
    }
    let mut t = tally(ok, qs.len());
    t["misses"] = json!(misses);
    t
}

pub(crate) fn ooc_block(real: &Retriever, ver: &str, qs: &[OocQ], cfg: &Config) -> Value {
    let mut ok = 0;
    let mut misses = vec![];
    for q in qs {
        let res = real.search(&q.query, Some(ver), 5, cfg);
        if res.verdict == Verdict::NotInCorpus {
            ok += 1;
        } else {
            misses.push(json!({"id": q.label, "got": got_of(&res)}));
        }
    }
    let mut t = tally(ok, qs.len());
    t["misses"] = json!(misses);
    t
}

pub(crate) fn inj_block(cases: &[InjCase], cfg: &Config) -> Value {
    let mut obeyed = vec![];
    let mut by_family = std::collections::BTreeMap::<String, (usize, usize)>::new();
    for c in cases {
        let o = score_injection(c, cfg);
        let e = by_family.entry(c.family.clone()).or_default();
        e.0 += 1;
        if o.obeyed {
            e.1 += 1;
            obeyed.push(
                json!({"id": c.label, "family": c.family, "expected": c.expected, "got": o.got, "ranked": o.ranked}),
            );
        }
    }
    json!({"n": cases.len(), "obeyed": obeyed.len(), "upper95_of_obeyed_rate": upper95(obeyed.len() as u64, cases.len() as u64),
           "by_family": by_family.iter().map(|(k, v)| (k.clone(), json!({"cases": v.0, "obeyed": v.1}))).collect::<serde_json::Map<_, _>>(),
           "misses": obeyed})
}

/// The configurations a report compares: the name list OFF is the one judged, ON is the ablation.
pub fn configs() -> (Config, Config) {
    let off = Config {
        unindexed_guard: false,
        ..Config::default()
    };
    let on = Config {
        unindexed_guard: true,
        ..Config::default()
    };
    (off, on)
}

/// Apply `name=value,name=value` overrides to a configuration (tuning on the DEV sets only).
pub fn apply_overrides(cfg: &mut Config, spec: &str) -> Result<(), String> {
    for kv in spec.split(',').filter(|x| !x.is_empty()) {
        let (k, v) = kv.split_once('=').ok_or("override must be name=value")?;
        let f = || v.parse::<f64>().map_err(|_| format!("bad number for {k}"));
        match k {
            "coverage_min" => cfg.coverage_min = f()?,
            "min_norm_score" => cfg.min_norm_score = f()?,
            "head_words" => cfg.head_words = f()? as usize,
            "head_weight" => cfg.head_weight = f()?,
            "tf_cap" => cfg.tf_cap = f()? as u32,
            "len_cap_mult" => cfg.len_cap_mult = f()?,
            "cov_exp" => cfg.cov_exp = f()?,
            "prose_penalty" => cfg.prose_penalty = f()?,
            "prose_stop_ratio" => cfg.prose_stop_ratio = f()?,
            "unknown_weight" => cfg.unknown_weight = f()?,
            "phrase_weight" => cfg.phrase_weight = f()?,
            "entity_mult" => cfg.entity_mult = f()?,
            "head_only_factor" => cfg.head_only_factor = f()?,
            "echo_terms" => cfg.echo_terms = f()? as usize,
            "parent_ratio" => cfg.parent_ratio = f()?,
            "entity_guard" => cfg.entity_guard = f()? != 0.0,
            "content_min_matched" => cfg.content_min_matched = f()? as usize,
            "content_cov_min" => cfg.content_cov_min = f()?,
            "structural_flags" => cfg.structural_flags = f()? != 0.0,
            "flag_factor" => cfg.flag_factor = f()?,
            "foreign_guard" => cfg.foreign_guard = f()? != 0.0,
            "raw_flags" => cfg.raw_flags = f()? != 0.0,
            "foreign_any_name" => cfg.foreign_any_name = f()? != 0.0,
            "density_min_tokens" => cfg.density_min_tokens = f()? as usize,
            other => return Err(format!("unknown parameter {other}")),
        }
    }
    Ok(())
}

/// Score the DEV sets (tuning only).
pub fn run_dev(real: &Retriever, ver: &str, d: &DevSets) -> Value {
    let (off, on) = configs();
    run_dev_with(real, ver, d, &off, &on)
}

/// [`run_dev`] with explicit configurations.
pub fn run_dev_with(real: &Retriever, ver: &str, d: &DevSets, off: &Config, on: &Config) -> Value {
    let (off, on) = (off.clone(), on.clone());
    json!({
        "description_only": desc_block(real, ver, &d.desc, &off),
        "out_of_corpus_name_list_off": ooc_block(real, ver, &d.ooc, &off),
        "out_of_corpus_name_list_on": ooc_block(real, ver, &d.ooc, &on),
        "out_of_corpus_2_name_list_off": ooc_block(real, ver, &d.ooc2, &off),
        "injection": inj_block(&d.inj, &off),
    })
}

/// Score the held-out sets: counts, bounds and ids only, never question text.
pub fn run_heldout(real: &Retriever, ver: &str, h: &HeldOut) -> Value {
    let (off, on) = configs();
    run_heldout_with(real, ver, h, &off, &on)
}

/// [`run_heldout`] with explicit configurations (`off` is judged, `on` is the ablation).
pub fn run_heldout_with(
    real: &Retriever,
    ver: &str,
    h: &HeldOut,
    off: &Config,
    on: &Config,
) -> Value {
    let (off, on) = (off.clone(), on.clone());
    let stale_ok: Vec<&StaleCase> = h.stale.iter().filter(|c| score_stale(c, &off)).collect();
    let stale_miss: Vec<&str> = h
        .stale
        .iter()
        .filter(|c| !score_stale(c, &off))
        .map(|c| c.label.as_str())
        .collect();
    json!({
        "description_only": desc_block(real, ver, &h.desc, &off),
        "id_named": desc_block(real, ver, &h.idn, &off),
        "out_of_corpus_name_list_off": ooc_block(real, ver, &h.ooc, &off),
        "out_of_corpus_name_list_on": ooc_block(real, ver, &h.ooc, &on),
        "injection": inj_block(&h.inj, &off),
        "stale_version": {"n": h.stale.len(), "passed": stale_ok.len(), "misses": stale_miss},
    })
}
