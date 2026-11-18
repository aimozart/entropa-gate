#![no_main]
use entropa_witness::{decode_statement, statement_canonical_bytes, statement_digest, verify_statement};
use libfuzzer_sys::fuzz_target;

// The statement decoder and the verification path never panic; a decoded statement has a stable digest;
// verification under an unrelated key never succeeds.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(st) = decode_statement(text) {
        let canon = statement_canonical_bytes(&st.fields);
        assert!(!canon.is_empty());
        assert_eq!(statement_digest(&canon), statement_digest(&canon));
        assert!(verify_statement(text, &"ab".repeat(1952)).is_err());
        assert!(verify_statement(text, &st.fields.witness_pubkey).is_err() || st.sig.len() == 6618);
    }
});
