//! One-off ops tool: derive `id:pubkey_hex` (both public, safe to display) from a
//! signing_key_hex read on stdin — lets a validator's public config be
//! reconstructed reliably from Secret Manager without ever displaying the secret
//! itself, or trusting it to be re-typed correctly from memory.
//!
//! Usage: gcloud secrets versions access latest --secret=NAME | \
//!        cargo run -q -p entropa-core --example pubkey_from_key
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;

use entropa_core::Probe;

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read stdin");
    let key_hex = input.trim();
    let probe = Probe::from_signing_key_hex(key_hex).expect("valid signing_key_hex on stdin");
    println!("{}:{}", probe.id(), probe.pubkey_hex());
}
