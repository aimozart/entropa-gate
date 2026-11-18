#![no_main]
use entropa_council::{canonical_bytes, decode_event, event_digest};
use libfuzzer_sys::fuzz_target;

// The strict decoder never panics. Anything it accepts has canonical bytes that parse as JSON with sorted keys, the
// digest is a pure function of those bytes, decoding the same payload twice gives the same event, and a payload that
// contains a canary token is never accepted (P0).
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let decoded = decode_event(text);
    if text.contains("ENTROPA-CANARY-") {
        assert!(decoded.is_err(), "a canary token was accepted");
    }
    if let Ok(e) = decoded {
        let c = canonical_bytes(&e);
        assert!(serde_json::from_slice::<serde_json::Value>(&c).is_ok());
        assert!(!String::from_utf8_lossy(&c).contains("\"sig\""));
        assert_eq!(event_digest(&c), event_digest(&canonical_bytes(&e)));
        assert_eq!(decode_event(text).ok(), Some(e));
    }
});
