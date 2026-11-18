#![no_main]
use entropa_ledger::{decode_event, encode_event, verify_event};
use libfuzzer_sys::fuzz_target;

// The strict event decoder never panics; anything it accepts re-encodes to a payload that decodes to the
// same event; verification under an unrelated key never succeeds and never panics.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(ev) = decode_event(text) {
        let again = decode_event(&encode_event(&ev).unwrap()).unwrap();
        assert_eq!(again, ev);
        assert!(verify_event(text, &"ab".repeat(1952)).is_err());
    }
});
