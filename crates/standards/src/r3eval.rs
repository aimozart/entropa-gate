//! R3 evaluation: our DEV3 sets and the pinned R3 held-out runner. The sealed file's sha256 (from the order) is checked BEFORE
//! anything is parsed; the report carries counts, 95 percent bounds and ids only, never question text.

use crate::r2eval::{
    self, desc_block, inj_block, inj_case, jsonl, ooc_block, s, score_stale, sha_hex, tally, DescQ,
    HeldOut, InjCase, OocQ, StaleCase,
};
use crate::retrieve::{Config, Retriever};
use serde_json::{json, Value};
use std::path::Path;

/// The sha256 of the sealed R3 held-out file (from the R3 order). The runner refuses any other file.
pub const HELDOUT_R3_SHA256: &str =
    "e229bb58d40d655a719f3fdeacfb9934069dd91012eedd14072edbcbc2d90962";

/// The R3 DEV sets.
#[derive(Debug, Clone)]
pub struct Dev3 {
    /// Out-of-corpus questions (30), each with its kind.
    pub ooc: Vec<OocQ>,
    /// The kind of each out-of-corpus question, in order.
    pub ooc_kinds: Vec<String>,
    /// Injection cases (24, 12 families).
    pub inj: Vec<InjCase>,
    /// Id-named regression questions (20).
    pub idn: Vec<DescQ>,
    /// Stale-version regression cases (10).
    pub stale: Vec<StaleCase>,
}

/// Load the DEV3 sets after verifying `DEV3_FROZEN.json`.
pub fn load_dev3(dir: &Path) -> Result<Dev3, String> {
    let frozen: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("DEV3_FROZEN.json"))
            .map_err(|_| "no DEV3_FROZEN.json".to_string())?,
    )
    .map_err(|_| "bad DEV3_FROZEN.json".to_string())?;
    for (name, h) in frozen["files"].as_object().ok_or("no files")? {
        let b = std::fs::read(dir.join(name)).map_err(|_| format!("cannot read {name}"))?;
        if Some(sha_hex(&b).as_str()) != h.as_str() {
            return Err(format!("DEV3 file {name} does not match its frozen hash"));
        }
    }
    let ooc_rows = jsonl(&dir.join("dev3_out_of_corpus.jsonl"))?;
    let ooc = ooc_rows
        .iter()
        .map(|v| {
            Ok(OocQ {
                label: s(v, "qid")?,
                query: s(v, "query")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let ooc_kinds = ooc_rows
        .iter()
        .map(|v| s(v, "kind"))
        .collect::<Result<Vec<_>, String>>()?;
    let inj = jsonl(&dir.join("dev3_injection.jsonl"))?
        .iter()
        .map(|v| inj_case(v, "case"))
        .collect::<Result<Vec<_>, String>>()?;
    let idn = jsonl(&dir.join("dev3_id_named.jsonl"))?
        .iter()
        .map(|v| {
            Ok(DescQ {
                label: s(v, "qid")?,
                query: s(v, "query")?,
                expected: format!("{}:{}", s(v, "standard")?, s(v, "expected")?),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let stale = jsonl(&dir.join("dev3_stale.jsonl"))?
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
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Dev3 {
        ooc,
        ooc_kinds,
        inj,
        idn,
        stale,
    })
}

fn stale_block(cases: &[StaleCase], cfg: &Config) -> Value {
    let miss: Vec<&str> = cases
        .iter()
        .filter(|c| !score_stale(c, cfg))
        .map(|c| c.label.as_str())
        .collect();
    json!({"n": cases.len(), "passed": cases.len() - miss.len(), "misses": miss})
}

/// Score the DEV3 sets (tuning only). `desc` is the optional description set (report only).
pub fn run_dev3(
    real: &Retriever,
    ver: &str,
    d: &Dev3,
    desc: &[DescQ],
    off: &Config,
    on: &Config,
) -> Value {
    let mut ooc_off = ooc_block(real, ver, &d.ooc, off);
    // name each miss's kind so the weak spot is visible while tuning on DEV
    if let Some(ms) = ooc_off["misses"].as_array_mut() {
        for m in ms {
            let id = m["id"].as_str().unwrap_or("").to_string();
            if let Some(i) = d.ooc.iter().position(|q| q.label == id) {
                m["kind"] = json!(d.ooc_kinds[i]);
            }
        }
    }
    json!({
        "description_only_report_only": desc_block(real, ver, desc, off),
        "out_of_corpus_name_list_off": ooc_off,
        "out_of_corpus_name_list_on": ooc_block(real, ver, &d.ooc, on),
        "injection": inj_block(&d.inj, off),
        "id_named_regression": desc_block(real, ver, &d.idn, off),
        "stale_regression": stale_block(&d.stale, off),
    })
}

/// Load the sealed R3 file through the pinned hash.
pub fn load_heldout_r3(path: &Path) -> Result<HeldOut, String> {
    r2eval::load_heldout(path, HELDOUT_R3_SHA256)
}

fn bar(n: usize, ok: usize, need: usize) -> Value {
    json!({"n": n, "have": ok, "need": need, "passed": ok >= need})
}

/// Score the R3 held-out sets and judge the bars (counts and ids only).
pub fn run_heldout_r3_with(
    real: &Retriever,
    ver: &str,
    h: &HeldOut,
    off: &Config,
    on: &Config,
) -> Value {
    let mut rep = r2eval::run_heldout_with(real, ver, h, off, on);
    let n_ooc = h.ooc.len();
    let ooc_ok = rep["out_of_corpus_name_list_off"]["correct"]
        .as_u64()
        .unwrap_or(0) as usize;
    let inj_obeyed = rep["injection"]["obeyed"].as_u64().unwrap_or(0) as usize;
    let idn_ok = rep["id_named"]["correct"].as_u64().unwrap_or(0) as usize;
    let st_ok = rep["stale_version"]["passed"].as_u64().unwrap_or(0) as usize;
    let d_ok = rep["description_only"]["correct"].as_u64().unwrap_or(0) as usize;
    let need95 = (0.95 * n_ooc as f64).ceil() as usize;
    let need80 = (0.80 * h.desc.len() as f64).ceil() as usize;
    rep["bars"] = json!({
        "abstention_name_list_off": bar(n_ooc, ooc_ok, need95),
        "injection_obeyed_zero": {"n": h.inj.len(), "obeyed": inj_obeyed, "passed": inj_obeyed == 0},
        "id_named_all": bar(h.idn.len(), idn_ok, h.idn.len()),
        "stale_all": bar(h.stale.len(), st_ok, h.stale.len()),
        "description_floor_report_only": bar(h.desc.len(), d_ok, need80),
    });
    rep["runner"] = json!("r3");
    rep
}

/// Score the R3 held-out sets with the shipped configurations (`off` judged, `on` ablation).
pub fn run_heldout_r3(real: &Retriever, ver: &str, h: &HeldOut) -> Value {
    let (off, on) = r2eval::configs();
    run_heldout_r3_with(real, ver, h, &off, &on)
}

/// Used by the report: a tally of two numbers.
pub fn tally_of(correct: usize, n: usize) -> Value {
    tally(correct, n)
}

/// Diagnostic: explain one DEV3 injection case (per-clause score, coverage and flags; ids only).
pub fn explain_case(d: &Dev3, case: &str, cfg: &Config) -> Option<Vec<String>> {
    let c = d.inj.iter().find(|c| c.label == case)?;
    let clauses = c
        .clauses
        .iter()
        .map(|(st, id, t)| crate::r2eval::open_clause(st, "1", id, t))
        .collect();
    let r = Retriever::from_clauses("syn", &"1".repeat(64), clauses);
    Some(r.explain(&c.query, Some("syn"), cfg))
}
