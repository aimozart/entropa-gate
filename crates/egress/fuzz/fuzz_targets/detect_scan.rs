#![no_main]
//! Every detector on every view kind: no panic, and every hit lies inside the scanned text on character boundaries.
use entropa_egress::detect::{scan_kind, ViewKind};
use entropa_egress::policy::{sign_dev, template_json, DevHashVerifier, Policy};
use libfuzzer_sys::fuzz_target;

const KEY: &[u8] = b"dev-verifier-key-not-a-signature";

fuzz_target!(|data: &[u8]| {
    let p = Policy::parse(&sign_dev(&template_json("api.model.example"), KEY), &DevHashVerifier::new(KEY)).expect("dev policy");
    let text = String::from_utf8_lossy(data).to_string();
    for kind in [ViewKind::Raw, ViewKind::Folded, ViewKind::Stripped, ViewKind::Decoded, ViewKind::Obfuscated] {
        for h in scan_kind(&text, kind, p.detect_cfg()) {
            assert!(h.start <= h.end && h.end <= text.len(), "hit out of range");
            assert!(text.is_char_boundary(h.start) && text.is_char_boundary(h.end), "hit inside a character");
        }
    }
});
