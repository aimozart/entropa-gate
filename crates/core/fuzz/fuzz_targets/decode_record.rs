#![no_main]
use entropa_core::transparency_log::{decode_record, encode_record};
use libfuzzer_sys::fuzz_target;

// 1. The strict decoder never panics, and anything it accepts is canonical:
//    encode(decode(b)) == b (exactly one valid byte string per record).
// 2. Any (payload, label) built from the input round-trips, and a different split of the
//    same bytes gives different encodings (injectivity, finding F4).
fuzz_target!(|data: &[u8]| {
    if let Ok((p, l)) = decode_record(data) {
        assert_eq!(encode_record(&p, l.as_deref()).unwrap(), data);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        for (i, _) in s.char_indices().chain(std::iter::once((s.len(), ' '))) {
            let (p, l) = s.split_at(i);
            let e = encode_record(p, Some(l)).unwrap();
            assert_eq!(decode_record(&e).unwrap(), (p.to_string(), Some(l.to_string())));
            assert_ne!(e, encode_record(s, None).unwrap());
        }
    }
});
