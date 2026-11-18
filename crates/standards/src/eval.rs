//! The evaluation harness for the FROZEN question sets (R1 task 3). It verifies the frozen hashes before and after, scores each set, and reports
//! every bar with counts and 95 percent upper bounds. It reads the sets; it never edits them, and it has no tuning parameters. The injection and
//! stale-version sets run against synthetic fixture corpora through the same tool core the MCP server uses.

use crate::chunk::{self, Format};
use crate::corpus::{text_sha256, Clause, Tier};
use crate::records::NullSink;
use crate::retrieve::{CiteVerdict, Config, Retriever, SearchResult, Verdict};
use crate::tools::{Server, TOOL_NAMES};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

/// What the system answered, reduced to what scoring needs.
#[derive(Debug, Clone)]
pub struct Answer {
    /// Answered or abstained.
    pub verdict: Verdict,
    /// The top passage as (standard, clause id).
    pub top: Option<(String, String)>,
    /// The reason code.
    pub reason: String,
}

/// Reduce a search result to an [`Answer`].
pub fn answer_of(r: &SearchResult) -> Answer {
    Answer {
        verdict: r.verdict,
        top: r
            .passages
            .first()
            .map(|p| (p.standard.clone(), p.clause_id.clone())),
        reason: r.reason.clone(),
    }
}

/// A clause-addressed question.
#[derive(Debug, Clone)]
pub struct Question {
    /// Question id.
    pub qid: String,
    /// The question text.
    pub query: String,
    /// Expected standard.
    pub standard: String,
    /// Expected clause id.
    pub expected: String,
    /// `id` or `description`.
    pub form: String,
}

/// An out-of-corpus question.
#[derive(Debug, Clone)]
pub struct OocQuestion {
    /// Question id.
    pub qid: String,
    /// The question text.
    pub query: String,
}

/// One wrong answer, by ids only.
#[derive(Debug, Clone, Serialize)]
pub struct Miss {
    /// Question id.
    pub qid: String,
    /// What was expected (`STANDARD:ID` or `abstain`).
    pub expected: String,
    /// What was returned (`STANDARD:ID` or `abstain:<reason>`).
    pub got: String,
}

/// One prediction row, ids and codes only.
#[derive(Debug, Clone, Serialize)]
pub struct Pred {
    /// The set the question belongs to.
    pub set: String,
    /// Question id.
    pub qid: String,
    /// Expected.
    pub expected: String,
    /// Got.
    pub got: String,
    /// Correct or not.
    pub correct: bool,
}

/// The score of a clause-addressed set.
#[derive(Debug, Clone, Serialize)]
pub struct ClauseScore {
    /// Questions.
    pub n: usize,
    /// Correct top-1 citations.
    pub correct: usize,
    /// (questions, correct) by form.
    pub by_form: BTreeMap<String, (usize, usize)>,
    /// (questions, correct) by standard.
    pub by_standard: BTreeMap<String, (usize, usize)>,
    /// The misses.
    pub misses: Vec<Miss>,
    /// Every prediction.
    pub predictions: Vec<Pred>,
}

/// The score of an abstention set.
#[derive(Debug, Clone, Serialize)]
pub struct AbstainScore {
    /// Questions.
    pub n: usize,
    /// Questions answered with an abstention.
    pub correct: usize,
    /// The misses.
    pub misses: Vec<Miss>,
    /// Every prediction.
    pub predictions: Vec<Pred>,
}

fn got_of(a: &Answer) -> String {
    match (&a.verdict, &a.top) {
        (Verdict::Answered, Some((s, i))) => format!("{s}:{i}"),
        _ => format!("abstain:{}", a.reason),
    }
}

/// 95 percent upper bound on the failure rate: the rule of three at zero failures, the Wilson bound otherwise.
pub fn upper95(failures: u64, n: u64) -> f64 {
    if n == 0 {
        return 1.0;
    }
    if failures == 0 {
        return (3.0 / n as f64).min(1.0);
    }
    let (n, p, z) = (n as f64, failures as f64 / n as f64, 1.959964_f64);
    let centre = p + z * z / (2.0 * n);
    let margin = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt();
    ((centre + margin) / (1.0 + z * z / n)).min(1.0)
}

/// Score a clause-addressed set: correct means the top-1 passage is the expected (standard, clause id).
pub fn score_clause_addressed(qs: &[Question], f: &dyn Fn(&str) -> Answer) -> ClauseScore {
    let mut s = ClauseScore {
        n: qs.len(),
        correct: 0,
        by_form: BTreeMap::new(),
        by_standard: BTreeMap::new(),
        misses: vec![],
        predictions: vec![],
    };
    for q in qs {
        let a = f(&q.query);
        let expected = format!("{}:{}", q.standard, q.expected);
        let got = got_of(&a);
        let ok = a.verdict == Verdict::Answered && got == expected;
        for (map, key) in [
            (&mut s.by_form, q.form.clone()),
            (&mut s.by_standard, q.standard.clone()),
        ] {
            let e = map.entry(key).or_insert((0, 0));
            e.0 += 1;
            e.1 += usize::from(ok);
        }
        s.correct += usize::from(ok);
        if !ok {
            s.misses.push(Miss {
                qid: q.qid.clone(),
                expected: expected.clone(),
                got: got.clone(),
            });
        }
        s.predictions.push(Pred {
            set: "clause_addressed".into(),
            qid: q.qid.clone(),
            expected,
            got,
            correct: ok,
        });
    }
    s
}

/// Score an out-of-corpus set: correct means the system abstained.
pub fn score_abstention(qs: &[OocQuestion], f: &dyn Fn(&str) -> Answer) -> AbstainScore {
    let mut s = AbstainScore {
        n: qs.len(),
        correct: 0,
        misses: vec![],
        predictions: vec![],
    };
    for q in qs {
        let a = f(&q.query);
        let ok = a.verdict == Verdict::NotInCorpus;
        s.correct += usize::from(ok);
        let got = got_of(&a);
        if !ok {
            s.misses.push(Miss {
                qid: q.qid.clone(),
                expected: "abstain".into(),
                got: got.clone(),
            });
        }
        s.predictions.push(Pred {
            set: "out_of_corpus".into(),
            qid: q.qid.clone(),
            expected: "abstain".into(),
            got,
            correct: ok,
        });
    }
    s
}

/// One bar with its count and bound.
#[derive(Debug, Clone, Serialize)]
pub struct Bar {
    /// Bar name.
    pub name: String,
    /// The rule as ordered.
    pub rule: String,
    /// Questions or cases.
    pub n: usize,
    /// Failures.
    pub failures: usize,
    /// Success rate.
    pub value: f64,
    /// 95 percent upper bound on the failure rate.
    pub upper95: f64,
    /// Passed or FAILED.
    pub passed: bool,
}

/// The four bars as ordered: citation accuracy at least 0.95, abstention at least 0.95, injection obeyed 0, stale-version all.
#[allow(clippy::too_many_arguments)]
pub fn bars(
    cite_ok: usize,
    cite_n: usize,
    abst_ok: usize,
    abst_n: usize,
    inj_obeyed: usize,
    inj_n: usize,
    stale_ok: usize,
    stale_n: usize,
) -> Vec<Bar> {
    let mk = |name: &str, rule: &str, n: usize, failures: usize, passed: bool| Bar {
        name: name.into(),
        rule: rule.into(),
        n,
        failures,
        value: if n == 0 {
            0.0
        } else {
            (n - failures) as f64 / n as f64
        },
        upper95: upper95(failures as u64, n as u64),
        passed,
    };
    vec![
        mk(
            "citation_accuracy",
            ">= 0.95 on the 60 clause-addressed questions",
            cite_n,
            cite_n - cite_ok,
            cite_ok * 100 >= 95 * cite_n,
        ),
        mk(
            "abstention",
            ">= 0.95 on the 20 out-of-corpus questions",
            abst_n,
            abst_n - abst_ok,
            abst_ok * 100 >= 95 * abst_n,
        ),
        mk(
            "injection_obeyed",
            "0 obeyed of 10",
            inj_n,
            inj_obeyed,
            inj_obeyed == 0,
        ),
        mk(
            "stale_version",
            "10 of 10",
            stale_n,
            stale_n - stale_ok,
            stale_ok == stale_n,
        ),
    ]
}

fn read_json(p: &Path) -> Result<Value, String> {
    serde_json::from_str(
        &std::fs::read_to_string(p).map_err(|_| format!("cannot read {}", p.display()))?,
    )
    .map_err(|_| format!("{} is not valid JSON", p.display()))
}
fn read_jsonl(p: &Path) -> Result<Vec<Value>, String> {
    std::fs::read_to_string(p)
        .map_err(|_| format!("cannot read {}", p.display()))?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|_| format!("bad line in {}", p.display())))
        .collect()
}
fn field(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| format!("missing {k}"))
}

/// Check every frozen file's sha256 and that nothing under `sets/` and `fixtures/` is unlisted.
pub fn verify_frozen(eval_dir: &Path) -> Result<(), String> {
    let fz = read_json(&eval_dir.join("FROZEN.json"))?;
    let files = fz
        .get("files")
        .and_then(Value::as_object)
        .ok_or("FROZEN.json has no files")?;
    for (rel, h) in files {
        let bytes = std::fs::read(eval_dir.join(rel))
            .map_err(|_| format!("{rel}: frozen file is missing"))?;
        if hex::encode(Sha256::digest(&bytes)) != h.as_str().unwrap_or("") {
            return Err(format!("{rel} changed after the freeze"));
        }
    }
    for d in ["sets", "fixtures"] {
        for e in std::fs::read_dir(eval_dir.join(d)).map_err(|_| format!("cannot read {d}"))? {
            let name = format!(
                "{d}/{}",
                e.map_err(|_| "read error")?.file_name().to_string_lossy()
            );
            if !files.contains_key(&name) {
                return Err(format!("{name} is not listed in FROZEN.json"));
            }
        }
    }
    Ok(())
}

/// Load the 60 clause-addressed questions.
pub fn load_clause_addressed(eval_dir: &Path) -> Result<Vec<Question>, String> {
    read_jsonl(&eval_dir.join("sets/clause_addressed.jsonl"))?
        .iter()
        .map(|v| {
            Ok(Question {
                qid: field(v, "qid")?,
                query: field(v, "query")?,
                standard: field(v, "standard")?,
                expected: field(v, "expected")?,
                form: field(v, "form")?,
            })
        })
        .collect()
}

/// Load the 20 out-of-corpus questions.
pub fn load_out_of_corpus(eval_dir: &Path) -> Result<Vec<OocQuestion>, String> {
    read_jsonl(&eval_dir.join("sets/out_of_corpus.jsonl"))?
        .iter()
        .map(|v| {
            Ok(OocQuestion {
                qid: field(v, "qid")?,
                query: field(v, "query")?,
            })
        })
        .collect()
}

/// the reviewer's independent subset, with the register ids mapped to corpus clauses by the frozen map.
pub struct Independent {
    /// The 15 clause questions.
    pub clause: Vec<Question>,
    /// The 5 out-of-corpus questions.
    pub out_of_corpus: Vec<OocQuestion>,
}

/// Load the independent subset.
pub fn load_independent(eval_dir: &Path) -> Result<Independent, String> {
    let sp = read_json(&eval_dir.join("sets/independent_questions.json"))?;
    let map = read_json(&eval_dir.join("sets/register_map.json"))?;
    let mut clause = Vec::new();
    for (i, q) in sp
        .get("clause_addressed")
        .and_then(Value::as_array)
        .ok_or("no clause_addressed")?
        .iter()
        .enumerate()
    {
        let reg = field(q, "expect")?;
        let t = map
            .get(&reg)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("no mapping for {reg}"))?;
        clause.push(Question {
            qid: format!("sp-{:02}", i + 1),
            query: field(q, "q")?,
            standard: t[0].as_str().unwrap_or("").into(),
            expected: t[1].as_str().unwrap_or("").into(),
            form: "description".into(),
        });
    }
    let out_of_corpus = sp
        .get("out_of_corpus")
        .and_then(Value::as_array)
        .ok_or("no out_of_corpus")?
        .iter()
        .enumerate()
        .map(|(i, q)| OocQuestion {
            qid: format!("spo-{:02}", i + 1),
            query: q.as_str().unwrap_or("").into(),
        })
        .collect();
    Ok(Independent {
        clause,
        out_of_corpus,
    })
}

/// Pure invariant checks over a tool result body.
pub mod check {
    use serde_json::Value;

    fn passages(b: &Value) -> Vec<&Value> {
        b.get("passages")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default()
    }
    /// The top passage is the expected `STANDARD:ID` and the answer was given.
    pub fn top1_is_expected(b: &Value, expect: &str) -> bool {
        b["verdict"] == "answered"
            && passages(b).first().is_some_and(|p| {
                format!(
                    "{}:{}",
                    p["standard"].as_str().unwrap_or(""),
                    p["clause_id"].as_str().unwrap_or("")
                ) == expect
            })
    }
    /// Every passage carries `untrusted: true`.
    pub fn passages_untrusted_marked(b: &Value) -> bool {
        passages(b).iter().all(|p| p["untrusted"] == true)
    }
    fn bad_char(c: char) -> bool {
        c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
    }
    fn strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
        match v {
            Value::String(s) => out.push(s),
            Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
            Value::Object(m) => m.values().for_each(|x| strings(x, out)),
            _ => {}
        }
    }
    /// No string anywhere in the result holds a control, bidirectional or zero-width character.
    pub fn no_control_or_bidi_characters(b: &Value) -> bool {
        let mut all = Vec::new();
        strings(b, &mut all);
        !all.iter().any(|s| s.chars().any(bad_char))
    }
    /// A lookup result holds a quote of at most 25 words and no full text.
    pub fn quote_max_25_words(b: &Value) -> bool {
        let p = &b["passage"];
        p.get("text").is_none()
            && p["quote"]
                .as_str()
                .is_some_and(|q| q.split_whitespace().count() <= 25)
    }
    /// An OPEN passage's text is at most 4,000 characters and marked truncated.
    pub fn text_capped_4000_and_truncated(b: &Value) -> bool {
        let p = &b["passage"];
        p["text"]
            .as_str()
            .is_some_and(|t| t.chars().count() <= 4000)
            && p["truncated"] == true
    }
    /// The verdict field equals `v`.
    pub fn verdict_is(b: &Value, v: &str) -> bool {
        b["verdict"] == v
    }
    /// The system abstained: not in corpus and no passages.
    pub fn abstains(b: &Value) -> bool {
        b["verdict"] == "not_in_corpus" && passages(b).is_empty()
    }
}

/// Result of one injection case.
#[derive(Debug, Clone, Serialize)]
pub struct InjectionResult {
    /// Case id.
    pub qid: String,
    /// The attack.
    pub attack: String,
    /// True if ANY invariant was violated.
    pub obeyed: bool,
    /// Invariants that were checked.
    pub checked: Vec<String>,
    /// Invariants that failed.
    pub failed: Vec<String>,
}

/// Result of one stale-version case.
#[derive(Debug, Clone, Serialize)]
pub struct StaleResult {
    /// Case id.
    pub qid: String,
    /// The clause.
    pub clause: String,
    /// All four checks held.
    pub ok: bool,
    /// Text hash returned under v1.
    pub v1_sha256: String,
    /// Text hash returned under v2.
    pub v2_sha256: String,
    /// What failed, if anything.
    pub detail: String,
}

/// Both fixture-based sets.
#[derive(Debug, Clone, Serialize)]
pub struct FixtureReport {
    /// The ten injection cases.
    pub injection: Vec<InjectionResult>,
    /// The ten stale-version cases.
    pub stale: Vec<StaleResult>,
}

fn fixture_clauses(
    eval_dir: &Path,
    file: &str,
    fmt: Format,
    standard: &str,
    ver: &str,
    tier: Tier,
) -> Result<Vec<Clause>, String> {
    let text = std::fs::read_to_string(eval_dir.join("fixtures").join(file))
        .map_err(|_| format!("cannot read fixture {file}"))?;
    Ok(chunk::chunk(fmt, &text)
        .map_err(|e| e.0)?
        .into_iter()
        .map(|c| Clause {
            standard: standard.into(),
            std_version: ver.into(),
            id: c.id,
            tier,
            text_sha256: text_sha256(&c.text),
            text: c.text,
        })
        .collect())
}

fn fixture_retriever(eval_dir: &Path) -> Result<Retriever, String> {
    let mut r = Retriever::from_clauses(
        "syn-inj-1",
        &"1".repeat(64),
        fixture_clauses(
            eval_dir,
            "inject_std.txt",
            Format::EuText,
            "SYN-INJ",
            "1",
            Tier::Open,
        )?,
    );
    r.add_clauses(
        "syn-lic-1",
        &"2".repeat(64),
        fixture_clauses(
            eval_dir,
            "inject_licensed.txt",
            Format::PciText,
            "SYN-LIC",
            "1",
            Tier::Licensed,
        )?,
    );
    r.add_clauses(
        "syn-stale-1",
        &"3".repeat(64),
        fixture_clauses(
            eval_dir,
            "stale_v1.txt",
            Format::EuText,
            "SYN-STALE",
            "1",
            Tier::Open,
        )?,
    );
    r.add_clauses(
        "syn-stale-2",
        &"4".repeat(64),
        fixture_clauses(
            eval_dir,
            "stale_v2.txt",
            Format::EuText,
            "SYN-STALE",
            "2",
            Tier::Open,
        )?,
    );
    Ok(r)
}

/// Run the injection and stale-version sets against the synthetic fixtures through the real tool core.
pub fn run_fixture_sets(eval_dir: &Path) -> Result<FixtureReport, String> {
    let retriever = fixture_retriever(eval_dir)?;
    let mut server = Server::new(fixture_retriever(eval_dir)?, Box::new(NullSink), "eval");
    let lic_text = fixture_clauses(
        eval_dir,
        "inject_licensed.txt",
        Format::PciText,
        "SYN-LIC",
        "1",
        Tier::Licensed,
    )?
    .into_iter()
    .find(|c| c.id == "1.1")
    .map(|c| c.text)
    .unwrap_or_default();
    let tail: String = lic_text
        .split_whitespace()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" ");
    let mut injection = Vec::new();
    for case in read_jsonl(&eval_dir.join("sets/injection.jsonl"))? {
        let tool = field(&case, "tool")?;
        let args = case.get("args").cloned().unwrap_or(Value::Null);
        let started = Instant::now();
        let out = if tool == "call_tool" {
            server.call(args["name"].as_str().unwrap_or(""), &args["arguments"])
        } else {
            server.call(&tool, &args)
        };
        let elapsed = started.elapsed();
        let body = out.body.clone();
        let mut checked = Vec::new();
        let mut failed = Vec::new();
        for inv in case
            .get("invariants")
            .and_then(Value::as_array)
            .ok_or("no invariants")?
        {
            let name = inv.as_str().unwrap_or("");
            let ok = match name {
                "top1_is_expected" => check::top1_is_expected(&body, &field(&case, "expect_top")?),
                "passages_untrusted_marked" => check::passages_untrusted_marked(&body),
                "verdict_is_expected" => check::verdict_is(&body, &field(&case, "expect_verdict")?),
                "quote_max_25_words" => check::quote_max_25_words(&body),
                "licensed_text_not_returned" => {
                    !body.to_string().contains(&tail) && body["passage"].get("text").is_none()
                }
                "only_four_read_tools" => {
                    Server::tools().iter().map(|t| t.name).collect::<Vec<_>>() == TOOL_NAMES
                }
                "unknown_tool_is_an_error" => out.is_error && body["error"] == "unknown_tool",
                "abstains" => check::abstains(&body),
                "no_control_or_bidi_characters" => check::no_control_or_bidi_characters(&body),
                "text_capped_4000_and_truncated" => check::text_capped_4000_and_truncated(&body),
                "answers_within_2_seconds" => elapsed.as_secs() < 2,
                other => return Err(format!("unknown invariant {other}")),
            };
            checked.push(name.to_string());
            if !ok {
                failed.push(name.to_string());
            }
        }
        injection.push(InjectionResult {
            qid: field(&case, "qid")?,
            attack: field(&case, "attack")?,
            obeyed: !failed.is_empty(),
            checked,
            failed,
        });
    }
    let cfg = Config::default();
    let mut stale = Vec::new();
    for case in read_jsonl(&eval_dir.join("sets/stale_version.jsonl"))? {
        let (std, clause, v1, v2) = (
            field(&case, "standard")?,
            field(&case, "clause")?,
            field(&case, "v1_version")?,
            field(&case, "v2_version")?,
        );
        let q = format!("Article {} of {std}", clause.trim_start_matches("Art."));
        let (r1, r2) = (
            retriever.search(&q, Some(&v1), 3, &cfg),
            retriever.search(&q, Some(&v2), 3, &cfg),
        );
        let (p1, p2) = (r1.passages.first(), r2.passages.first());
        let (h1, h2) = (
            p1.map(|p| p.text_sha256.clone()).unwrap_or_default(),
            p2.map(|p| p.text_sha256.clone()).unwrap_or_default(),
        );
        let mut why = Vec::new();
        if !p1.is_some_and(|p| {
            p.text
                .as_deref()
                .is_some_and(|t| t.contains(&field(&case, "v1_contains").unwrap_or_default()))
        }) {
            why.push("v1 text");
        }
        if !p2.is_some_and(|p| {
            p.text
                .as_deref()
                .is_some_and(|t| t.contains(&field(&case, "v2_contains").unwrap_or_default()))
        }) {
            why.push("v2 text");
        }
        if retriever.cite_check(&std, &clause, &v1, &h1) != CiteVerdict::Ok {
            why.push("cite ok under v1");
        }
        if !matches!(
            retriever.cite_check(&std, &clause, &v2, &h1),
            CiteVerdict::Drift { .. }
        ) {
            why.push("cite drift under v2");
        }
        stale.push(StaleResult {
            qid: field(&case, "qid")?,
            clause,
            ok: why.is_empty(),
            v1_sha256: h1,
            v2_sha256: h2,
            detail: why.join(", "),
        });
    }
    Ok(FixtureReport { injection, stale })
}

/// Abstention results with and without the unindexed-standard guard.
#[derive(Debug, Clone, Serialize)]
pub struct OocReport {
    /// The shipped configuration (the bar is judged on this).
    pub guard_on: AbstainScore,
    /// The ablation: the same frozen questions with the guard switched off.
    pub guard_off: AbstainScore,
}

/// The independent subset's results, reported as a separate sub-line.
#[derive(Debug, Clone, Serialize)]
pub struct IndependentReport {
    /// The 15 description-only clause questions.
    pub clause_addressed: ClauseScore,
    /// The 5 out-of-corpus questions with the guard on.
    pub out_of_corpus_guard_on: AbstainScore,
    /// The same with the guard off.
    pub out_of_corpus_guard_off: AbstainScore,
    /// Upper bound on the clause failure rate.
    pub clause_upper95: f64,
}

/// The whole report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// The corpus version evaluated.
    pub corpus_version: String,
    /// Its corpus hash.
    pub corpus_hash: String,
    /// The four bars.
    pub bars: Vec<Bar>,
    /// The 60 clause-addressed questions.
    pub clause_addressed: ClauseScore,
    /// The 20 out-of-corpus questions.
    pub out_of_corpus: OocReport,
    /// the reviewer's independent subset.
    pub independent_subset: IndependentReport,
    /// The injection cases.
    pub injection: Vec<InjectionResult>,
    /// The stale-version cases.
    pub stale_version: Vec<StaleResult>,
    /// Every prediction row (ids and codes only).
    pub predictions: Vec<Pred>,
    /// Plain notes that travel with the numbers.
    pub notes: Vec<String>,
}

/// Assemble the report from the scoring functions' answers.
#[allow(clippy::too_many_arguments)]
pub fn assemble(
    cq: &[Question],
    clause_f: &dyn Fn(&str) -> Answer,
    oc: &[OocQuestion],
    ooc_on: &dyn Fn(&str) -> Answer,
    ooc_off: &dyn Fn(&str) -> Answer,
    sp: &Independent,
    sp_clause_f: &dyn Fn(&str) -> Answer,
    sp_ooc_on: &dyn Fn(&str) -> Answer,
    sp_ooc_off: &dyn Fn(&str) -> Answer,
    fixtures: FixtureReport,
    corpus_version: &str,
    corpus_hash: &str,
) -> Report {
    let clause = score_clause_addressed(cq, clause_f);
    let on = score_abstention(oc, ooc_on);
    let off = score_abstention(oc, ooc_off);
    let sp_clause = score_clause_addressed(&sp.clause, sp_clause_f);
    let sp_on = score_abstention(&sp.out_of_corpus, sp_ooc_on);
    let sp_off = score_abstention(&sp.out_of_corpus, sp_ooc_off);
    let obeyed = fixtures.injection.iter().filter(|c| c.obeyed).count();
    let stale_ok = fixtures.stale.iter().filter(|s| s.ok).count();
    let mut predictions = clause.predictions.clone();
    predictions.extend(on.predictions.iter().cloned().map(|mut p| {
        p.set = "out_of_corpus_guard_on".into();
        p
    }));
    predictions.extend(off.predictions.iter().cloned().map(|mut p| {
        p.set = "out_of_corpus_guard_off".into();
        p
    }));
    predictions.extend(sp_clause.predictions.iter().cloned().map(|mut p| {
        p.set = "independent_clause".into();
        p
    }));
    predictions.extend(sp_on.predictions.iter().cloned().map(|mut p| {
        p.set = "independent_ooc_guard_on".into();
        p
    }));
    predictions.extend(sp_off.predictions.iter().cloned().map(|mut p| {
        p.set = "independent_ooc_guard_off".into();
        p
    }));
    let bars = bars(
        clause.correct,
        clause.n,
        on.correct,
        on.n,
        obeyed,
        fixtures.injection.len(),
        stale_ok,
        fixtures.stale.len(),
    );
    let upper = upper95((sp_clause.n - sp_clause.correct) as u64, sp_clause.n as u64);
    let kinds: BTreeSet<&str> = ["ISO", "SOC 2", "HITRUST", "NIS2", "CNSA 2.0"]
        .into_iter()
        .collect();
    let notes = vec![
        format!("The sealed corpus covers only five sources (NIST SP 800-53 Rev 5.2.0, EU AI Act, DORA RTS 2024/1774, HIPAA 164.312 from a Cornell mirror, PCI DSS 4.0.1). Questions about {} are out of corpus and must abstain.", kinds.iter().cloned().collect::<Vec<_>>().join(", ")),
        "The bar on abstention is judged on the shipped configuration (the unindexed-standard guard ON). The guard-off line is an ablation of the same frozen questions; a large difference means the guard, not the retrieval gate, does the work.".into(),
        "self-written sets are not independent of the author; the independent subset is the author-independent check and is reported as its own sub-line.".into(),
        "Injection and stale-version cases use synthetic fixtures through the same tool core as the MCP server.".into(),
    ];
    Report {
        corpus_version: corpus_version.into(),
        corpus_hash: corpus_hash.into(),
        bars,
        clause_addressed: clause,
        out_of_corpus: OocReport {
            guard_on: on,
            guard_off: off,
        },
        independent_subset: IndependentReport {
            clause_addressed: sp_clause,
            out_of_corpus_guard_on: sp_on,
            out_of_corpus_guard_off: sp_off,
            clause_upper95: upper,
        },
        injection: fixtures.injection,
        stale_version: fixtures.stale,
        predictions,
        notes,
    }
}

/// Run the whole evaluation on the real sealed corpus. The frozen hashes are checked before and after.
pub fn run_real(
    real: &Retriever,
    eval_dir: &Path,
    corpus_version: &str,
    corpus_hash: &str,
) -> Result<Report, String> {
    verify_frozen(eval_dir)?;
    let cq = load_clause_addressed(eval_dir)?;
    let oc = load_out_of_corpus(eval_dir)?;
    let sp = load_independent(eval_dir)?;
    let on = Config {
        unindexed_guard: true,
        ..Config::default()
    };
    let off = Config {
        unindexed_guard: false,
        ..Config::default()
    };
    let run =
        |cfg: Config| move |q: &str| answer_of(&real.search(q, Some(corpus_version), 5, &cfg));
    let report = assemble(
        &cq,
        &run(on.clone()),
        &oc,
        &run(on.clone()),
        &run(off.clone()),
        &sp,
        &run(on.clone()),
        &run(on),
        &run(off),
        run_fixture_sets(eval_dir)?,
        corpus_version,
        corpus_hash,
    );
    verify_frozen(eval_dir)?;
    Ok(report)
}

/// A JSON summary of the bars for the terminal.
pub fn summary(r: &Report) -> Value {
    json!({
        "corpus_version": r.corpus_version, "corpus_hash": r.corpus_hash,
        "bars": r.bars.iter().map(|b| json!({"name": b.name, "rule": b.rule, "n": b.n, "failures": b.failures, "value": b.value, "upper95_of_failure_rate": b.upper95, "status": if b.passed {"PASSED"} else {"FAILED"}})).collect::<Vec<_>>(),
    })
}
