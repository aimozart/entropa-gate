//! EG1f pipeline v2 (a stage record (not published)): the existing guard (`decide`, unchanged) plus the context detector, and the contained form.
use crate::contain::{Refusal, Schema};
use crate::context;
use crate::decide::{decide, Action, Conversation, Request};
use crate::detect::{self, Det, DetectCfg, ViewKind};
use crate::policy::{Policy, Tier};
use crate::record::RecordSink;

/// The outcome of the v2 pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// What to do.
    pub action: Action,
    /// A closed reason word.
    pub reason: String,
    /// The redacted body when the action is Redact.
    pub redacted: Option<Vec<u8>>,
}

/// The v2 pipeline on one request: the existing guard (`decide`, unchanged), then the context detector.
/// - If the guard allowed or redacted and the detector finds a value assigned to a secret key context, the answer is a BLOCK with the reason `context_secret` (the detector can only add blocks here).
/// - If the guard BLOCKED only because of its heuristic credential rule (detector D3, raw view, no attachments), and the detector sees that every such match is an assignment of a REFERENCE or a
///   placeholder (a variable, an environment or vault read, a call, a template) and finds no secret, the block is lifted: the guard's heuristic is wrong on harmless assignments (PowerShell and PHP).
///   Every other block stands.
pub fn decide_v2(
    req: &Request,
    policy: &Policy,
    tier: Tier,
    conv: &Conversation,
    sink: &dyn RecordSink,
) -> Outcome {
    let d = decide(req, policy, tier, conv, sink);
    let v1 = Outcome {
        action: d.action(),
        reason: d.reason().as_str().to_string(),
        redacted: d.redacted_body().map(<[u8]>::to_vec),
    };
    let text = String::from_utf8_lossy(&req.body).into_owned();
    let plain = !req.body_is_json && req.attachments.is_empty() && req.headers.is_empty();
    let units = units_of(req, &text);
    let an = if plain {
        context::analyze(&text)
    } else {
        // several units (JSON leaves, attachments, headers): one finding in any of them counts; the downgrade below is only for a plain text body
        let mut a = context::Analysis::default();
        for u in &units {
            let x = context::analyze(u);
            a.secrets.extend(x.secrets);
            a.references.extend(x.references);
        }
        a
    };
    match d.action() {
        Action::Allow | Action::Redact => {
            if an.secrets.is_empty() {
                v1
            } else {
                Outcome {
                    action: Action::Block,
                    reason: "context_secret".to_string(),
                    redacted: None,
                }
            }
        }
        Action::Block => {
            let only_d3 = !d.detectors().is_empty() && d.detectors().keys().all(|k| *k == Det::D3);
            let raw_only = d.views().iter().all(|v| *v == ViewKind::Raw);
            if plain
                && only_d3
                && raw_only
                && req.attachments.is_empty()
                && an.secrets.is_empty()
                && !an.references.is_empty()
            {
                let cfg = DetectCfg {
                    terms: vec![],
                    markers: vec![],
                    marker_key: vec![],
                    examples: vec![],
                };
                let d3: Vec<_> = detect::scan(&text, &cfg)
                    .into_iter()
                    .filter(|h| h.det == Det::D3)
                    .collect();
                let covered = |h: &detect::Hit| {
                    an.references
                        .iter()
                        .any(|r| r.start < h.end && h.start < r.end)
                };
                if !d3.is_empty() && d3.iter().all(covered) {
                    return Outcome {
                        action: Action::Allow,
                        reason: "clean".to_string(),
                        redacted: None,
                    };
                }
            }
            v1
        }
    }
}

/// The texts the context detector reads: for a JSON body every string leaf (decoded, so escapes cannot hide a quote) and every `key: value` pair whose value is a string; for a plain body the body;
/// then every attachment and every header as `name: value`.
fn units_of(req: &Request, text: &str) -> Vec<String> {
    fn walk(v: &serde_json::Value, depth: usize, out: &mut Vec<String>) {
        if depth > 64 || out.len() > 20_000 {
            return;
        }
        match v {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, depth + 1, out)),
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    if let serde_json::Value::String(s) = x {
                        out.push(format!("{k}: \"{}\"", s.replace('"', "'")));
                    }
                    walk(x, depth + 1, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    if req.body_is_json {
        match serde_json::from_str::<serde_json::Value>(text) {
            Ok(v) => walk(&v, 0, &mut out),
            Err(_) => out.push(text.to_string()),
        }
    } else {
        out.push(text.to_string());
    }
    for a in &req.attachments {
        out.push(String::from_utf8_lossy(&a.bytes).into_owned());
    }
    for (k, v) in &req.headers {
        out.push(format!("{k}: {v}"));
    }
    out
}

/// The development destination the contained form uses when the caller names none (the runner and the tests use the same policy host).
pub const DEV_DESTINATION: &str = "https://api.model.example/v1/chat";

/// The contained form to a named destination: the payload is checked against the schema first (a refusal is an error), then every free-text value goes through `decide_v2`; the worst action wins
/// (Block over Redact over Allow). A payload with no free text is allowed.
pub fn decide_contained_to(
    destination: &str,
    schema: &Schema,
    payload: &[u8],
    policy: &Policy,
    tier: Tier,
    conv: &Conversation,
    sink: &dyn RecordSink,
) -> Result<Outcome, Refusal> {
    let contained = crate::contain::check(schema, payload)?;
    let mut worst = Outcome {
        action: Action::Allow,
        reason: "clean".to_string(),
        redacted: None,
    };
    for (_, text) in contained.free_text {
        let req = Request {
            destination: destination.to_string(),
            body: text.into_bytes(),
            body_is_json: false,
            attachments: vec![],
            headers: vec![],
        };
        let o = decide_v2(&req, policy, tier, conv, sink);
        let rank = |a: Action| match a {
            Action::Allow => 0,
            Action::Redact => 1,
            Action::Block => 2,
        };
        if rank(o.action) > rank(worst.action) {
            worst = o;
        }
    }
    Ok(worst)
}

/// The contained form to the development destination (see [`decide_contained_to`]).
pub fn decide_contained(
    schema: &Schema,
    payload: &[u8],
    policy: &Policy,
    tier: Tier,
    conv: &Conversation,
    sink: &dyn RecordSink,
) -> Result<Outcome, Refusal> {
    decide_contained_to(DEV_DESTINATION, schema, payload, policy, tier, conv, sink)
}
