#![no_main]
use entropa_ledger::{verify_bundle, Generator, MemoryStore};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn good_bundle() -> &'static String {
    static B: OnceLock<String> = OnceLock::new();
    B.get_or_init(|| {
        let mut g = Generator::new(
            1,
            include_str!("../../../../policies/entropa.cedarschema"),
            include_str!("../../../../policies/entropa.cedar"),
        )
        .unwrap();
        let mut store = MemoryStore::default();
        g.run(&mut store, 6, 1_700_000_000).unwrap();
        g.export_bundle(&store).unwrap()
    })
}

// The standalone bundle verifier never panics on arbitrary text, nor on a valid bundle with one byte
// changed (the mutation position and value come from the input).
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = verify_bundle(text);
    }
    if data.len() >= 3 {
        let mut bytes = good_bundle().as_bytes().to_vec();
        let pos = (usize::from(data[0]) << 8 | usize::from(data[1])).wrapping_mul(97) % bytes.len();
        bytes[pos] ^= data[2] | 1;
        if let Ok(text) = String::from_utf8(bytes) {
            let _ = verify_bundle(&text);
        }
    }
});
