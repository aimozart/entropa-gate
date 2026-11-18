#![no_main]
use libfuzzer_sys::fuzz_target;

// Deserializing an untrusted receipt/checkpoint must never panic, and verifying whatever
// parses must never panic either.
fuzz_target!(|data: &[u8]| {
    if let Ok(r) = serde_json::from_slice::<entropa_core::transparency_log::Receipt>(data) {
        let _ = entropa_core::transparency_log::verify_receipt(&r, &r.checkpoint.proposer_pubkey);
    }
    let _ = serde_json::from_slice::<entropa_core::transparency_log::Checkpoint>(data);
});
