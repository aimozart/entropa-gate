#![no_main]
//! A policy file is untrusted input: parsing arbitrary text, signed or not, never panics.
use entropa_egress::policy::{sign_dev, DevHashVerifier, Policy};
use libfuzzer_sys::fuzz_target;

const KEY: &[u8] = b"dev-verifier-key-not-a-signature";

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).to_string();
    let v = DevHashVerifier::new(KEY);
    let _ = Policy::parse(&text, &v);
    let _ = Policy::parse(&sign_dev(&text, KEY), &v);
});
