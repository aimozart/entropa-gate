//! `entropa-guard [--tier T0|T1|T2|T3]`: read text on standard input and print `allow` or `block` (one word, one line). The check is the egress engine with its built-in demonstration policy
//! (one destination, `api.model.example`); text that the engine would only redact is blocked, because a wrapper cannot send redacted text. The reason code goes to standard error as `reason: <code>`;
//! the text is never printed. Exit 0 allow, 1 block (also for input that cannot be checked: empty, NUL, not UTF-8, over 64 KiB), 2 usage. It is a heuristic with known misses, not a complete secret filter.
#![allow(clippy::print_stdout, clippy::print_stderr)]
use entropa_egress::decide::{decide, Action, Conversation, Request};
use entropa_egress::policy::{sign_dev, template_json, DevHashVerifier, Policy, Tier};
use entropa_egress::record::{EvidenceRequest, RecordSink};
use std::io::Read;

const MAX_BYTES: u64 = 64 * 1024;
const USAGE: &str =
    "usage: entropa-guard [--tier T0|T1|T2|T3]   (text on standard input; prints allow or block)";

struct NullSink;
impl RecordSink for NullSink {
    fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
        Ok(())
    }
}

fn block(reason: &str) -> ! {
    println!("block");
    eprintln!("reason: {reason}");
    std::process::exit(1);
}

fn tier_from_args(args: &[String]) -> Result<Tier, ()> {
    match args {
        [] => Ok(Tier::T1),
        [flag, value] if flag == "--tier" => match value.as_str() {
            "T0" => Ok(Tier::T0),
            "T1" => Ok(Tier::T1),
            "T2" => Ok(Tier::T2),
            "T3" => Ok(Tier::T3),
            _ => Err(()),
        },
        _ => Err(()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Ok(tier) = tier_from_args(&args) else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    let mut bytes = Vec::new();
    if std::io::stdin()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        block("invalid_input");
    }
    if bytes.is_empty()
        || bytes.len() as u64 > MAX_BYTES
        || bytes.contains(&0)
        || std::str::from_utf8(&bytes).is_err()
    {
        block("invalid_input");
    }
    let key = b"entropa-guard-demo-policy-key";
    let signed = sign_dev(&template_json("api.model.example"), key);
    let Ok(policy) = Policy::parse(&signed, &DevHashVerifier::new(key)) else {
        block("internal_error");
    };
    let request = Request {
        destination: "https://api.model.example/v1/chat".into(),
        body: bytes,
        body_is_json: false,
        attachments: vec![],
        headers: vec![],
    };
    let conv = Conversation {
        key: b"entropa-guard-conversation".to_vec(),
        tail: String::new(),
        seen: vec![],
    };
    let d = decide(&request, &policy, tier, &conv, &NullSink);
    match d.action() {
        Action::Allow => println!("allow"),
        Action::Redact | Action::Block => block(d.reason().as_str()),
    }
}
