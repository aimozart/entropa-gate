#![no_main]
//! The views map every character back to a raw byte range; the ranges must lie inside the raw text and on character boundaries, or a redaction
//! slice would panic.
use entropa_egress::views::{decoded, fold, strip};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data).to_string();
    for v in [fold(&raw), strip(&raw)] {
        assert_eq!(v.spans.len(), v.text.chars().count());
        for &(a, b) in &v.spans {
            assert!(a <= b && b <= raw.len(), "span out of range");
            assert!(raw.is_char_boundary(a) && raw.is_char_boundary(b), "span inside a character");
        }
    }
    for d in decoded(&raw) {
        assert!(d.src.0 <= d.src.1 && d.src.1 <= raw.len());
        assert!(raw.is_char_boundary(d.src.0) && raw.is_char_boundary(d.src.1));
    }
});
