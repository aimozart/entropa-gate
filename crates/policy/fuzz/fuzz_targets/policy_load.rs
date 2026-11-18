#![no_main]
use entropa_policy::Engine;
use libfuzzer_sys::fuzz_target;

// Loading arbitrary schema and policy text never panics; the text is split at the first NUL.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (schema, policies) = text.split_once('\0').unwrap_or((text, ""));
    if let Ok(engine) = Engine::new(schema, policies) {
        assert_eq!(engine.policy_set_hash().len(), 64);
    }
});
