#![no_main]
use entropa_mcp::{Server, TOOL_NAMES};
use libfuzzer_sys::fuzz_target;

// Arbitrary bytes, parsed as JSON when possible, are fed to every tool as arguments. The server
// must never panic and must always answer with a JSON object body.
fuzz_target!(|data: &[u8]| {
    let Ok(args) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let mut server = Server::new(Vec::new(), None);
    for (i, tool) in TOOL_NAMES.iter().enumerate() {
        // spread calls over time so the rate limiter does not mask the argument parsing
        let out = server.call_at(tool, &args, (i as u64) * 120_000);
        assert!(out.body.is_object());
    }
});
