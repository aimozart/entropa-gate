#![no_main]
use entropa_policy::decode_record;
use libfuzzer_sys::fuzz_target;

// The strict record decoder never panics; anything it accepts decodes again to the same record.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(rec) = decode_record(text) {
        assert_eq!(decode_record(&rec.payload).unwrap(), rec);
    }
});
