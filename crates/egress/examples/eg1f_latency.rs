//! EG1f latency of pipeline v2 against v1 (the guard alone) at 1, 16 and 64 KiB, two body shapes: plain prose with one planted synthetic key at the end (as `egress-eval latency`), and a
//! worst case for the context detector: 64 KiB made only of key words and assignments. Prints JSON (percentiles in milliseconds; never any request text). Run in release.
//! Usage: cargo run --release --offline -p entropa-egress --example eg1f_latency [runs]
#![allow(missing_docs, clippy::unwrap_used, clippy::print_stdout)]
use entropa_egress::decide::{decide, Conversation, Request};
use entropa_egress::eval::{load_policy, policy_from_extra};
use entropa_egress::policy::Tier;
use entropa_egress::record::{EvidenceRequest, RecordSink};
use entropa_egress::v2::decide_v2;
use serde_json::json;
use std::time::Instant;

struct Null;
impl RecordSink for Null {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        Ok(())
    }
}

fn prose(bytes: usize) -> String {
    let words = [
        "supplier", "schedule", "review", "storage", "recovery", "deploy", "quarter", "risk",
        "update", "owner", "retention", "policy",
    ];
    let (mut t, mut i) = (String::new(), 0);
    while t.len() + 64 < bytes {
        t.push_str(words[i % words.len()]);
        t.push(if i % 11 == 10 { '\n' } else { ' ' });
        i += 1;
    }
    t.push_str("AKIAIOSFODNN7EXAMPLE");
    t
}
fn keywords(bytes: usize) -> String {
    let unit = "the password = $env:DB_PWD_X and secret: reviewed then api_key=${VAULT_KEY} token -> hunter_value\n";
    let mut t = String::new();
    while t.len() + unit.len() < bytes {
        t.push_str(unit);
    }
    t
}

fn pct(ms: &mut [f64]) -> serde_json::Value {
    ms.sort_by(|a, b| a.total_cmp(b));
    let at = |q: f64| ms[((ms.len() as f64 * q).ceil() as usize).saturating_sub(1)];
    json!({"p50_ms": at(0.50), "p95_ms": at(0.95), "p99_ms": at(0.99), "max_ms": ms[ms.len() - 1]})
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(200);
    let policy = load_policy(&policy_from_extra(&json!({}))).unwrap();
    let conv = Conversation {
        key: b"latency-key".to_vec(),
        tail: String::new(),
        seen: vec![],
    };
    let mut out = vec![];
    for (shape, make) in [("prose_with_one_key", prose as fn(usize) -> String), ("keyword_dense", keywords)] {
        for bytes in [1024usize, 16384, 65536] {
            let req = Request {
                destination: "https://api.model.example/v1/chat".into(),
                body: make(bytes).into_bytes(),
                body_is_json: false,
                attachments: vec![],
                headers: vec![],
            };
            let (mut v1, mut v2) = (vec![], vec![]);
            for i in 0..(n + 3) {
                let t = Instant::now();
                let _ = decide(&req, &policy, Tier::T1, &conv, &Null);
                let a = t.elapsed().as_secs_f64() * 1000.0;
                let t = Instant::now();
                let _ = decide_v2(&req, &policy, Tier::T1, &conv, &Null);
                let b = t.elapsed().as_secs_f64() * 1000.0;
                if i >= 3 {
                    v1.push(a);
                    v2.push(b);
                }
            }
            out.push(json!({"shape": shape, "bytes": req.body.len(), "runs": n, "v1": pct(&mut v1), "v2": pct(&mut v2)}));
        }
    }
    println!("{}", serde_json::to_string_pretty(&json!({"note": "wall clock on the machine that ran it, release build; v2 = guard plus context detector (the guard runs inside v2, so v2 includes v1)", "results": out})).unwrap());
}
