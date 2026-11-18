//! The evaluation runner: DEV sets and the sealed set share it. It reads cases (JSON lines), runs `decide`, and reports counts, bounds and
//! ids only, never request text. A "leak" is a request holding a planted value that is allowed or redacted with the value still recoverable from
//! the bytes that would be sent (raw, folded, stripped or decoded view), or a split secret that gets through at all.
use crate::decide::{decide, Action, Attachment, Conversation, Request};
use crate::policy::{sign_dev, template_json, DevHashVerifier, Policy, Tier};
use crate::record::{EvidenceRequest, RecordSink};
use crate::views::{decoded, strip};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// The verifier key the DEV and sealed policies are signed with. It is a test hash, not a signature scheme.
pub const DEV_KEY: &[u8] = b"dev-verifier-key-not-a-signature";
/// Default destination.
pub const DEST: &str = "https://api.model.example/v1/chat";

struct Null(RefCell<u64>);
impl RecordSink for Null {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        *self.0.borrow_mut() += 1;
        Ok(())
    }
}

/// Build the signed DEV policy from the template plus the extra terms, markers and key of a set.
pub fn policy_from_extra(extra: &Value) -> String {
    let mut v: Value =
        serde_json::from_str(&template_json("api.model.example")).unwrap_or(Value::Null);
    let terms: Vec<Value> = extra["terms"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|t| json!({"words":[t],"whole_word":true,"all":true}))
                .collect()
        })
        .unwrap_or_default();
    v["terms"] = Value::Array(terms);
    v["markers"] = extra.get("markers").cloned().unwrap_or(json!([]));
    v["marker_key"] = extra.get("marker_key").cloned().unwrap_or(json!(""));
    sign_dev(&v.to_string(), DEV_KEY)
}
/// Parse a signed policy text with the DEV verifier.
pub fn load_policy(text: &str) -> Result<Policy, String> {
    Policy::parse(text, &DevHashVerifier::new(DEV_KEY)).map_err(|e| format!("{e:?}"))
}

/// Upper 95 percent bound of a rate: exact one-sided for zero, Wilson otherwise (stated in the report).
pub fn upper95(k: usize, n: usize) -> f64 {
    if n == 0 {
        return 1.0;
    }
    if k == 0 {
        return 1.0 - 0.05f64.powf(1.0 / n as f64);
    }
    let (p, nf, z) = (k as f64 / n as f64, n as f64, 1.645f64);
    let d = 1.0 + z * z / nf;
    ((p + z * z / (2.0 * nf) + z * (p * (1.0 - p) / nf + z * z / (4.0 * nf * nf)).sqrt()) / d)
        .min(1.0)
}

fn json_leaves(v: &Value, out: &mut String) {
    match v {
        Value::String(s) => out.push_str(s),
        Value::Array(a) => a.iter().for_each(|x| json_leaves(x, out)),
        Value::Object(m) => m.iter().for_each(|(_, x)| json_leaves(x, out)),
        _ => {}
    }
}
fn norm(s: &str) -> String {
    strip(s).text
}
/// Is any planted value recoverable from the sent text?
pub fn recoverable(sent: &str, planted: &[String]) -> bool {
    let mut texts = vec![sent.to_string()];
    if let Ok(v) = serde_json::from_str::<Value>(sent) {
        let mut j = String::new();
        json_leaves(&v, &mut j);
        texts.push(j);
    }
    let mut views: Vec<String> = Vec::new();
    for t in &texts {
        views.push(norm(t));
        for d in decoded(t) {
            views.push(norm(&d.text));
        }
    }
    planted.iter().filter(|p| !p.is_empty()).any(|p| {
        let np = norm(p);
        views.iter().any(|v| v.contains(&np))
    })
}

/// One case outcome.
pub struct Outcome {
    /// The action taken.
    pub action: Action,
    /// The case passed its expectation.
    pub pass: bool,
}

/// Which pipeline the runner uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pipeline {
    /// The guard as sealed in round 5 (default).
    V1,
    /// The guard plus the context detector (EG1f).
    V2,
}

/// Run one case against a policy with the v1 pipeline.
pub fn run_case(c: &Value, policy: &Policy) -> Result<Outcome, String> {
    run_case_with(c, policy, Pipeline::V1)
}

/// Run one case against a policy with the chosen pipeline.
pub fn run_case_with(c: &Value, policy: &Policy, pipeline: Pipeline) -> Result<Outcome, String> {
    let s = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let tier: Tier = c
        .get("tier")
        .and_then(Value::as_str)
        .unwrap_or("T1")
        .parse()
        .map_err(|_| "tier".to_string())?;
    let body: Vec<u8> = match c.get("body_hex").and_then(Value::as_str) {
        Some(h) => hex::decode(h).map_err(|e| e.to_string())?,
        None => s("body").into_bytes(),
    };
    let attachments: Vec<Attachment> = c
        .get("attachments")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| Attachment {
                    name: x["name"].as_str().unwrap_or("").into(),
                    mime: x["mime"].as_str().unwrap_or("").into(),
                    bytes: x["text"].as_str().unwrap_or("").as_bytes().to_vec(),
                })
                .collect()
        })
        .unwrap_or_default();
    let headers: Vec<(String, String)> = c
        .get("headers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| {
                    (
                        x[0].as_str().unwrap_or("").into(),
                        x[1].as_str().unwrap_or("").into(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let req = Request {
        destination: c
            .get("destination")
            .and_then(Value::as_str)
            .unwrap_or(DEST)
            .to_string(),
        body,
        body_is_json: c
            .get("body_is_json")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        attachments: attachments.clone(),
        headers,
    };
    let conv = Conversation {
        key: b"eval-conversation-key".to_vec(),
        tail: s("tail"),
        seen: vec![],
    };
    let sink = Null(RefCell::new(0));
    let (action, redacted_body): (Action, Option<Vec<u8>>) = match pipeline {
        Pipeline::V1 => {
            let d = decide(&req, policy, tier, &conv, &sink);
            (d.action(), d.redacted_body().map(<[u8]>::to_vec))
        }
        Pipeline::V2 => {
            let o = crate::v2::decide_v2(&req, policy, tier, &conv, &sink);
            (o.action, o.redacted)
        }
    };
    let planted: Vec<String> = c
        .get("planted")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let expect = s("expect");
    let pass = match expect.as_str() {
        "allow" => action == Action::Allow,
        "either" => true,
        "block" => action == Action::Block,
        "no_leak" => {
            if action == Action::Block {
                true
            } else if !s("tail").is_empty() {
                false
            } else {
                let mut sent = match redacted_body.as_deref() {
                    Some(b) => String::from_utf8_lossy(b).into_owned(),
                    None => String::from_utf8_lossy(&req.body).into_owned(),
                };
                for a in &attachments {
                    sent.push('\n');
                    sent.push_str(&String::from_utf8_lossy(&a.bytes));
                }
                !recoverable(&sent, &planted)
            }
        }
        other => return Err(format!("unknown expect {other}")),
    };
    Ok(Outcome { action, pass })
}

/// Per-class results.
#[derive(Default)]
pub struct ClassResult {
    /// Cases.
    pub n: usize,
    /// Failed ids.
    pub failed: Vec<String>,
    /// Per family: (cases, failures).
    pub families: BTreeMap<String, (usize, usize)>,
    /// Action counts.
    pub actions: BTreeMap<String, usize>,
}

/// Run a list of cases (already parsed); returns per-class results.
pub fn run_cases(
    cases: &[Value],
    policy: &Policy,
) -> Result<BTreeMap<String, ClassResult>, String> {
    run_cases_with(cases, policy, Pipeline::V1)
}

/// Run many cases with the chosen pipeline.
pub fn run_cases_with(
    cases: &[Value],
    policy: &Policy,
    pipeline: Pipeline,
) -> Result<BTreeMap<String, ClassResult>, String> {
    let mut out: BTreeMap<String, ClassResult> = BTreeMap::new();
    for c in cases {
        let class = c["class"].as_str().unwrap_or("?").to_string();
        let fam = c["family"].as_str().unwrap_or("?").to_string();
        let id = c["id"].as_str().unwrap_or("?").to_string();
        let o = run_case_with(c, policy, pipeline)?;
        let r = out.entry(class).or_default();
        r.n += 1;
        let f = r.families.entry(fam).or_default();
        f.0 += 1;
        if !o.pass {
            f.1 += 1;
            r.failed.push(id);
        }
        *r.actions
            .entry(format!("{:?}", o.action).to_lowercase())
            .or_default() += 1;
    }
    Ok(out)
}

/// The report of a run: counts, bounds, ids only.
pub fn report(results: &BTreeMap<String, ClassResult>) -> Value {
    let mut classes = serde_json::Map::new();
    for (k, r) in results {
        let fam: serde_json::Map<String, Value> = r
            .families
            .iter()
            .map(|(f, (n, x))| (f.clone(), json!({"cases": n, "failed": x})))
            .collect();
        classes.insert(k.clone(), json!({"cases": r.n, "failed": r.failed.len(), "upper95_of_failure_rate": upper95(r.failed.len(), r.n), "failed_ids": r.failed, "families": fam, "actions": r.actions}));
    }
    json!({"bound_method": "exact one-sided 95 percent for zero failures (1 - 0.05^(1/n)); Wilson upper otherwise", "classes": classes})
}

/// The clean-text cost of the engine on a set of clause texts: counts per outcome and per detector, with ids only.
pub fn clause_cost(clauses: &[(String, String, String)], policy: &Policy) -> Value {
    let mut by_action: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_det: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (std, id, text) in clauses {
        let req = Request {
            destination: DEST.into(),
            body: text.clone().into_bytes(),
            body_is_json: false,
            attachments: vec![],
            headers: vec![],
        };
        let conv = Conversation {
            key: b"eval-conversation-key".to_vec(),
            tail: String::new(),
            seen: vec![],
        };
        let d = decide(&req, policy, Tier::T3, &conv, &Null(RefCell::new(0)));
        *by_action
            .entry(format!("{:?}", d.action()).to_lowercase())
            .or_default() += 1;
        for det in d.detectors().keys() {
            by_det
                .entry(det.as_str().to_string())
                .or_default()
                .push(format!("{std}:{id}"));
        }
    }
    let dets: serde_json::Map<String, Value> = by_det
        .iter()
        .map(|(k, v)| (k.clone(), json!({"clauses": v.len(), "ids": v})))
        .collect();
    json!({"clauses": clauses.len(), "actions": by_action, "by_detector": dets})
}

/// Latency of `decide` in milliseconds at three request sizes (1, 16 and 64 KiB of synthetic prose with one planted synthetic key at the end),
/// `n` timed runs each after a warm-up. Reports percentiles and the count of `internal_error` decisions; never any request text.
pub fn latency(n: usize) -> Result<Value, String> {
    use crate::decide::Reason;
    use std::time::Instant;
    let policy = load_policy(&policy_from_extra(&json!({})))?;
    let words = [
        "supplier",
        "schedule",
        "review",
        "storage",
        "recovery",
        "deploy",
        "quarter",
        "risk",
        "update",
        "owner",
        "retention",
        "policy",
    ];
    let mut sizes = Vec::new();
    for bytes in [1024usize, 16384, 65536] {
        let mut text = String::new();
        let mut i = 0;
        while text.len() + 64 < bytes {
            text.push_str(words[i % words.len()]);
            text.push(if i % 11 == 10 { '\n' } else { ' ' });
            i += 1;
        }
        text.push_str("AKIAIOSFODNN7EXAMPLE");
        let req = Request {
            destination: DEST.to_string(),
            body: text.into_bytes(),
            body_is_json: false,
            attachments: vec![],
            headers: vec![],
        };
        let conv = Conversation {
            key: b"latency-key".to_vec(),
            tail: String::new(),
            seen: vec![],
        };
        let run = || decide(&req, &policy, Tier::T1, &conv, &Null(RefCell::new(0)));
        for _ in 0..3 {
            run();
        }
        let mut ms: Vec<f64> = Vec::with_capacity(n);
        let mut internal = 0;
        for _ in 0..n {
            let t = Instant::now();
            let d = run();
            ms.push(t.elapsed().as_secs_f64() * 1000.0);
            if d.reason() == Reason::InternalError {
                internal += 1;
            }
        }
        ms.sort_by(|a, b| a.total_cmp(b));
        let at = |q: f64| {
            ms.get(((ms.len() as f64 * q).ceil() as usize).saturating_sub(1))
                .copied()
                .unwrap_or(0.0)
        };
        sizes.push(json!({"bytes": bytes, "p50_ms": at(0.50), "p95_ms": at(0.95), "p99_ms": at(0.99), "max_ms": ms.last().copied().unwrap_or(0.0), "internal_errors": internal}));
    }
    Ok(
        json!({"runs_per_size": n, "sizes": sizes, "note": "one planted synthetic key per request; wall clock on the machine that ran it; build profile as run"}),
    )
}
