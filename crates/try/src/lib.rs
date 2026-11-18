//! LS3a (a stage record (not published)): the contract of the public "Try the gate" handler.
//! The handler is a PURE function: no network, no clock (the caller passes `now`), no filesystem, no logging of the text.
use entropa_core::Probe;
use entropa_egress::decide::{decide, Action, Conversation, Request};
use entropa_egress::policy::{sign_dev, template_json, DevHashVerifier, Policy, Tier};
use entropa_egress::record::{EvidenceRequest, RecordSink};
use entropa_ledger::{encode_event, sign_event};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// The label every successful answer carries.
pub const LABEL: &str = "mock data, real signed records";

/// The closed list of error codes.
pub const ERROR_CODES: [&str; 12] = [
    "too_large",
    "bad_content_type",
    "not_utf8",
    "not_json",
    "duplicate_key",
    "unknown_field",
    "missing_field",
    "bad_type",
    "bad_tier",
    "invalid_text",
    "rate_limited",
    "not_implemented",
];

/// Limits of one service instance.
#[derive(Debug, Clone)]
pub struct Config {
    /// Largest accepted body in bytes.
    pub max_body: usize,
    /// Requests one client may make per window.
    pub rate_capacity: u32,
    /// The window in seconds.
    pub rate_window_secs: u64,
    /// The most clients the limiter remembers (the longest-unseen are forgotten first).
    pub max_clients: usize,
    /// Mixed into every hash the service makes (client keys, texts). The default is a fixed domain string: a deployment must set a random value (LS3b).
    pub salt: Vec<u8>,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            max_body: 4096,
            rate_capacity: 10,
            rate_window_secs: 60,
            max_clients: 10_000,
            salt: b"entropa-try-default-salt-v1".to_vec(),
        }
    }
}

/// What the HTTP layer hands over: the content type, an opaque client key (never stored as given) and the body.
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest<'a> {
    /// The Content-Type header value.
    pub content_type: &'a str,
    /// An opaque client key (for example an address); only a salted hash is kept.
    pub client: &'a str,
    /// The raw body.
    pub body: &'a [u8],
}

/// What the HTTP layer sends back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The JSON body.
    pub body: String,
    /// Seconds to wait (only for 429).
    pub retry_after_secs: Option<u64>,
}

struct NullSink;
impl RecordSink for NullSink {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Default)]
struct Limiter {
    // client hash -> (window start, count in the window, last-seen sequence number)
    by_client: HashMap<[u8; 16], (u64, u32, u64)>,
    // last-seen sequence number -> client hash: the smallest is the longest-unseen
    by_age: BTreeMap<u64, [u8; 16]>,
    seq: u64,
}

/// One service instance.
pub struct Service {
    signer: Probe,
    cfg: Config,
    policy: Option<Policy>,
    limiter: Mutex<Limiter>,
}

fn answer(status: u16, body: Value) -> Response {
    Response {
        status,
        body: body.to_string(),
        retry_after_secs: None,
    }
}
fn error(status: u16, code: &'static str) -> Response {
    answer(status, json!({ "error": code }))
}

impl Service {
    /// A service signing records with `signer` (a throwaway key made at start-up).
    pub fn new(signer: Probe, cfg: Config) -> Service {
        let key = b"entropa-try-dev-policy-key";
        let signed = sign_dev(&template_json("api.model.example"), key);
        let policy = Policy::parse(&signed, &DevHashVerifier::new(key)).ok();
        Service {
            signer,
            cfg,
            policy,
            limiter: Mutex::new(Limiter::default()),
        }
    }

    /// The number of clients the limiter currently remembers.
    pub fn tracked_clients(&self) -> usize {
        self.limiter.lock().map_or(0, |l| l.by_client.len())
    }

    fn hash(&self, parts: &[&[u8]]) -> blake3::Hash {
        let mut h = blake3::Hasher::new();
        h.update(&self.cfg.salt);
        for p in parts {
            h.update(&(p.len() as u64).to_be_bytes());
            h.update(p);
        }
        h.finalize()
    }

    /// Count this request for its client; `Err(seconds)` when the client is over the limit.
    fn rate(&self, client: &str, now: u64) -> Result<(), u64> {
        let mut key = [0u8; 16];
        key.copy_from_slice(&self.hash(&[b"client", client.as_bytes()]).as_bytes()[..16]);
        let mut l = match self.limiter.lock() {
            Ok(l) => l,
            Err(p) => p.into_inner(),
        };
        l.seq += 1;
        let seq = l.seq;
        let (start, count) = match l.by_client.get(&key).copied() {
            Some((start, count, old)) => {
                l.by_age.remove(&old);
                if now >= start + self.cfg.rate_window_secs {
                    (now, 0)
                } else {
                    (start, count)
                }
            }
            None => {
                while l.by_client.len() >= self.cfg.max_clients.max(1) {
                    let Some((&oldest, &victim)) = l.by_age.iter().next() else {
                        break;
                    };
                    l.by_age.remove(&oldest);
                    l.by_client.remove(&victim);
                }
                (now, 0)
            }
        };
        l.by_age.insert(seq, key);
        if count >= self.cfg.rate_capacity {
            l.by_client.insert(key, (start, count, seq));
            return Err((start + self.cfg.rate_window_secs)
                .saturating_sub(now)
                .max(1));
        }
        l.by_client.insert(key, (start, count + 1, seq));
        Ok(())
    }

    /// Handle one request at time `now` (seconds).
    pub fn handle(&self, req: &HttpRequest<'_>, now: u64) -> Response {
        if let Err(wait) = self.rate(req.client, now) {
            let mut r = error(429, "rate_limited");
            r.retry_after_secs = Some(wait);
            return r;
        }
        if req.body.len() > self.cfg.max_body {
            return error(413, "too_large");
        }
        let media = req
            .content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if media != "application/json" {
            return error(415, "bad_content_type");
        }
        let Ok(text) = std::str::from_utf8(req.body) else {
            return error(400, "not_utf8");
        };
        let Ok(parsed) = serde_json::from_str::<Value>(text) else {
            return error(400, "not_json");
        };
        let Some(obj) = parsed.as_object() else {
            return error(400, "not_json");
        };
        if entropa_witness::strict_json::has_duplicate_keys(text) {
            return error(400, "duplicate_key");
        }
        if obj.keys().any(|k| k != "text" && k != "tier") {
            return error(400, "unknown_field");
        }
        let (Some(t), Some(tier)) = (obj.get("text"), obj.get("tier")) else {
            return error(400, "missing_field");
        };
        let (Some(t), Some(tier)) = (t.as_str(), tier.as_str()) else {
            return error(400, "bad_type");
        };
        let tier_e = match tier {
            "T0" => Tier::T0,
            "T1" => Tier::T1,
            "T2" => Tier::T2,
            "T3" => Tier::T3,
            _ => return error(400, "bad_tier"),
        };
        if t.is_empty() || t.contains('\0') {
            return error(400, "invalid_text");
        }
        self.decide_and_sign(t, tier, tier_e, now)
    }

    fn decide_and_sign(&self, text: &str, tier: &str, tier_e: Tier, now: u64) -> Response {
        let request = Request {
            destination: "https://api.model.example/v1/chat".into(),
            body: text.as_bytes().to_vec(),
            body_is_json: false,
            attachments: vec![],
            headers: vec![],
        };
        let conv = Conversation {
            key: b"entropa-try-conversation".to_vec(),
            tail: String::new(),
            seen: vec![],
        };
        // the built-in policy is a constant the egress crate's own tests parse; if it ever failed to parse, every answer would be a 500, never a panic
        let Some(policy) = &self.policy else {
            return error(500, "internal_error");
        };
        let d = decide(&request, policy, tier_e, &conv, &NullSink);
        let (word, ledger_decision, reason, passed, flagged) = match d.action() {
            Action::Allow => ("allow", "allow", "within_limits", 1, 0),
            Action::Redact => ("redact", "allow", "within_limits", 1, 1),
            Action::Block => ("block", "deny", "guard_refused", 0, 1),
        };
        let text_hash = self.hash(&[b"text", text.as_bytes()]).to_hex().to_string();
        let run_id = self
            .hash(&[b"run", text.as_bytes(), tier.as_bytes()])
            .to_hex()
            .to_string();
        let evidence = json!({
            "kind": "evidence.policy", "label": "policy_verdict", "decision": ledger_decision, "reason": reason,
            "control": "hitrust_01_access_control", "total": 1, "passed": passed, "flagged": flagged,
            "detail": text_hash, "run_id": run_id, "ts": now,
        });
        let pubkey = self.signer.pubkey_hex();
        let event = entropa_nodecore::evidence_event(&evidence.to_string(), &pubkey)
            .map_err(|e| e.to_string())
            .and_then(|f| sign_event(&self.signer, &f).map_err(|e| format!("{e:?}")))
            .and_then(|e| {
                encode_event(&e)
                    .map_err(|e| format!("{e:?}"))
                    .map(|p| (p, e))
            });
        let Ok((payload, ev)) = event else {
            return error(500, "internal_error");
        };
        let mut body = json!({
            "label": LABEL, "tier": tier, "decision": word, "reasons": [d.reason().as_str()],
            "record": { "event": payload, "key_id": ev.fields.key_id, "pubkey": pubkey },
        });
        if word == "redact" {
            body["redacted"] = json!(true);
            body["note"] = json!("Parts of the text were redacted. The record is an allow of the redacted text; the ledger has no separate word for redaction.");
        }
        answer(200, body)
    }
}
