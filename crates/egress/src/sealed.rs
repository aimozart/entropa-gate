//! The sealed-set runner for the schema `eg-sealed-v1` (private repository `a private plan file`). It reads the set, builds each request
//! exactly as given, runs the guard with the file's own policy, and reports counts, bounds and ids only. A leak is a canary found byte for byte in
//! the bytes the sender would transmit; a block is never a leak.
use crate::decide::{decide, Action, Attachment, Conversation, Reason, Request};
use crate::eval::{upper95, DEV_KEY};
use crate::policy::{sign_dev, template_json, DevHashVerifier, Policy, Tier};
use crate::record::{EvidenceRequest, RecordSink};
use base64::Engine;
use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;

struct Null(RefCell<u64>);
impl RecordSink for Null {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        *self.0.borrow_mut() += 1;
        Ok(())
    }
}

/// Build one policy per set from the file's `policy` object. Unknown detector ids are counted and ignored.
pub fn build_policy(p: &Value) -> Result<(Policy, usize), String> {
    let mut v: Value =
        serde_json::from_str(&template_json("placeholder.invalid")).map_err(|e| e.to_string())?;
    // destinations: group url prefixes by (scheme, host, port)
    let mut dests: BTreeMap<(String, String, u16), Vec<String>> = BTreeMap::new();
    for d in p["destinations"].as_array().cloned().unwrap_or_default() {
        let url = d["url_prefix"].as_str().unwrap_or("");
        let u =
            crate::policy::parse_url(url).ok_or_else(|| "destination url_prefix".to_string())?;
        let tier = d["tier"].as_str().unwrap_or("").to_string();
        dests
            .entry((u.scheme, u.host, u.port))
            .or_default()
            .push(tier);
    }
    let list: Vec<Value> = dests.iter().enumerate().map(|(i, ((s, h, port), t))| json!({"id": format!("d{}", i + 1), "scheme": s, "host": h, "port": port, "allow_tiers": t})).collect();
    v["destinations"] = Value::Array(list);
    let mut ignored = 0;
    if let Some(m) = p["modes"].as_object() {
        for tier in ["T1", "T2", "T3"] {
            for (k, mode) in m {
                if crate::detect::Det::parse(k).is_some() {
                    v["detectors"][tier][k] = mode.clone();
                } else {
                    ignored += 1;
                }
            }
        }
    }
    let terms: Vec<Value> = p["do_not_send_terms"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|t| json!({"words": [t], "whole_word": true, "all": true}))
                .collect()
        })
        .unwrap_or_default();
    v["terms"] = Value::Array(terms);
    let text = sign_dev(&v.to_string(), DEV_KEY);
    let pol = Policy::parse(&text, &DevHashVerifier::new(DEV_KEY))
        .map_err(|e| format!("policy refused: {e:?}"))?;
    Ok((pol, ignored / 3))
}

/// The bytes the sender would transmit, as one string, from the request as built and the decision.
fn sent_bytes(req: &Request, redacted: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(req.destination.as_bytes());
    out.push(b'\n');
    for (n, v) in &req.headers {
        out.extend_from_slice(format!("{n}: {v}\n").as_bytes());
    }
    out.extend_from_slice(redacted.unwrap_or(&req.body));
    for a in &req.attachments {
        out.push(b'\n');
        out.extend_from_slice(&a.bytes);
    }
    out
}
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn build_request(c: &Value) -> Result<Request, String> {
    let r = &c["request"];
    let (body, is_json) = match r.get("raw_body_b64").and_then(Value::as_str) {
        Some(b) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b)
                .map_err(|e| e.to_string())?;
            let json = bytes
                .iter()
                .find(|x| !x.is_ascii_whitespace())
                .is_some_and(|x| matches!(x, b'{' | b'['));
            (bytes, json)
        }
        None => {
            let mut m = Map::new();
            if let Some(f) = r["body_fields"].as_object() {
                for (k, v) in f {
                    m.insert(k.clone(), v.clone());
                }
            }
            (
                serde_json::to_vec(&Value::Object(m)).map_err(|e| e.to_string())?,
                true,
            )
        }
    };
    let attachments = r["attachments"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|a| {
            let mut bytes = a["text"].as_str().unwrap_or("").as_bytes().to_vec();
            let size = a["size"].as_u64().unwrap_or(0).min(64 << 20) as usize;
            if bytes.len() < size {
                bytes.resize(size, b' ');
            }
            Attachment {
                name: "attachment".into(),
                mime: a["type"].as_str().unwrap_or("").into(),
                bytes,
            }
        })
        .collect();
    let headers = r["headers"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default();
    Ok(Request {
        destination: r["destination"].as_str().unwrap_or("").to_string(),
        body,
        body_is_json: is_json,
        attachments,
        headers,
    })
}

#[derive(Default)]
struct Acc {
    cases: usize,
    evaluated: usize,
    failed: Vec<String>,
    report_only_cases: usize,
    report_only_leaks: Vec<String>,
    either: BTreeMap<String, usize>,
    actions: BTreeMap<String, usize>,
    reasons: BTreeMap<String, usize>,
    internal_errors: Vec<String>,
    subs: BTreeMap<String, (usize, usize)>,
}

/// Run a parsed sealed set with the v1 pipeline (the guard as sealed in round 5). Returns the report (counts, bounds and ids only).
pub fn run_set(set: &Value, sha: &str) -> Result<Value, String> {
    run_set_with(set, sha, crate::eval::Pipeline::V1)
}

/// Run a parsed sealed set with the chosen pipeline.
pub fn run_set_with(
    set: &Value,
    sha: &str,
    pipeline: crate::eval::Pipeline,
) -> Result<Value, String> {
    if set["schema"].as_str() != Some("eg-sealed-v1") {
        return Err("schema must be eg-sealed-v1".into());
    }
    let (pol, ignored) = build_policy(&set["policy"])?;
    let mut classes: BTreeMap<String, Acc> = BTreeMap::new();
    for c in set["cases"].as_array().ok_or("cases")? {
        let class = c["class"].as_str().unwrap_or("?").to_string();
        let sub = c["subclass"].as_str().unwrap_or("?").to_string();
        let id = c["id"].as_str().unwrap_or("?").to_string();
        let tier: Tier = c["tier"]
            .as_str()
            .unwrap_or("T1")
            .parse()
            .map_err(|_| format!("tier of {id}"))?;
        let req = build_request(c)?;
        let conv = Conversation {
            key: b"sealed-run-key".to_vec(),
            tail: String::new(),
            seen: vec![],
        };
        let sink = Null(RefCell::new(0));
        let (action, reason, redacted): (Action, String, Option<Vec<u8>>) = match pipeline {
            crate::eval::Pipeline::V1 => {
                let d = decide(&req, &pol, tier, &conv, &sink);
                (
                    d.action(),
                    d.reason().as_str().to_string(),
                    d.redacted_body().map(<[u8]>::to_vec),
                )
            }
            crate::eval::Pipeline::V2 => {
                let o = crate::v2::decide_v2(&req, &pol, tier, &conv, &sink);
                (o.action, o.reason, o.redacted)
            }
        };
        let a = classes.entry(class).or_default();
        a.cases += 1;
        *a.actions
            .entry(format!("{:?}", action).to_lowercase())
            .or_default() += 1;
        *a.reasons.entry(reason.clone()).or_default() += 1;
        if reason == Reason::InternalError.as_str() {
            a.internal_errors.push(id.clone());
        }
        let canaries: Vec<&str> = c["canaries"]
            .as_array()
            .map(|x| x.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let leaked = action != Action::Block && {
            let sent = sent_bytes(&req, redacted.as_deref());
            canaries.iter().any(|k| contains(&sent, k.as_bytes()))
        };
        let expect = c["expect"].as_str().unwrap_or("?");
        let (counted, pass) = match expect {
            "no_leak" => (true, !leaked),
            "block" => (true, action == Action::Block),
            "allow" => (true, action == Action::Allow),
            "either" => {
                *a.either
                    .entry(format!("{:?}", action).to_lowercase())
                    .or_default() += 1;
                (false, true)
            }
            "no_leak_report_only" => {
                a.report_only_cases += 1;
                if leaked {
                    a.report_only_leaks.push(id.clone());
                }
                (false, true)
            }
            other => return Err(format!("unknown expect {other} in {id}")),
        };
        let s = a.subs.entry(sub).or_default();
        s.0 += 1;
        if counted {
            a.evaluated += 1;
            if !pass {
                a.failed.push(id);
                s.1 += 1;
            }
        }
    }
    let mut out = Map::new();
    for (k, a) in &classes {
        let subs: Map<String, Value> = a
            .subs
            .iter()
            .map(|(s, (n, f))| (s.clone(), json!({"cases": n, "failed": f})))
            .collect();
        out.insert(k.clone(), json!({
            "cases": a.cases, "evaluated": a.evaluated, "failed": a.failed.len(), "upper95_of_failure_rate": upper95(a.failed.len(), a.evaluated),
            "failed_ids": a.failed, "report_only": {"cases": a.report_only_cases, "leaks": a.report_only_leaks.len(), "leak_ids": a.report_only_leaks},
            "either_counts": a.either, "actions": a.actions, "reasons": a.reasons, "internal_error_ids": a.internal_errors, "subclasses": subs
        }));
    }
    Ok(
        json!({"schema": "eg-sealed-report-v1", "set_sha256": sha, "ignored_unknown_detector_modes": ignored,
        "bound_method": "exact one-sided 95 percent for zero failures (1 - 0.05^(1/n)); Wilson upper otherwise", "classes": out}),
    )
}
