#![no_main]
use entropa_approvals::{decode, encode};
use libfuzzer_sys::fuzz_target;

// The strict decoder never panics, and anything it accepts re-encodes to a payload that decodes
// to the same event (the encoding is canonical for accepted input).
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(event) = decode(text) {
        let again = encode(&event).unwrap();
        assert_eq!(decode(&again).unwrap(), event);
    }
});
