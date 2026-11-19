#![no_main]
use entropa_witness::anchor_file::{decode_anchor, encode_anchor};
use libfuzzer_sys::fuzz_target;

// The strict anchor decoder never panics; anything it accepts re-encodes to a canonical line that decodes to the same anchor and log id.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok((a, log_id)) = decode_anchor(text) {
        let line = encode_anchor(&a, &log_id);
        assert!(!line.contains('\n'));
        assert_eq!(decode_anchor(&line).unwrap(), (a, log_id));
    }
});
