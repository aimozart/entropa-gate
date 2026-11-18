//! Example: prints the decision the handler gives for a few harmless texts at each tier (no identifier-shaped values).
#![allow(clippy::unwrap_used)]
use entropa_core::Probe;
use entropa_try::{Config, HttpRequest, Service};
fn main() {
    let s = Service::new(
        Probe::from_signing_key_hex(&"0b".repeat(32)).unwrap(),
        Config {
            rate_capacity: 100_000,
            ..Config::default()
        },
    );
    for (i, text) in ["mail me at jane.doe@example.invalid please", "hello"]
        .iter()
        .enumerate()
    {
        for t in ["T0", "T1"] {
            let b = serde_json::json!({"text": text, "tier": t}).to_string();
            let r = s.handle(
                &HttpRequest {
                    content_type: "application/json",
                    client: &format!("c{i}{t}"),
                    body: b.as_bytes(),
                },
                1_800_000_000,
            );
            println!("{t} {} {}", r.status, r.body.len());
        }
    }
}
