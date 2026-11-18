#![no_main]
use entropa_witness::{decode_request, Request};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

// The strict request decoder never panics; anything it accepts re-encodes to a body that decodes to the same request.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(r) = decode_request(text) {
        let again: Request = decode_request(
            &json!({"v": 1, "log_id": r.log_id, "checkpoint": serde_json::to_value(&r.checkpoint).unwrap(),
                    "consistency": r.consistency.iter().map(hex::encode).collect::<Vec<_>>()})
            .to_string(),
        )
        .unwrap();
        assert_eq!(again, r);
    }
});
