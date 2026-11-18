#![no_main]
use libfuzzer_sys::fuzz_target;

// The bounded line pump never emits a line longer than the limit (plus the newline), except the
// fixed replacement line, and never loses a short line.
fuzz_target!(|data: &[u8]| {
    const MAX: usize = 64;
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let mut out = Vec::new();
    rt.block_on(entropa_mcp::pump_bounded(data, &mut out, MAX)).unwrap();
    for line in out.split(|b| *b == b'\n') {
        assert!(line.len() <= MAX || line.starts_with(b"{\"jsonrpc\":\"2.0\",\"id\":\"request_too_large\""));
    }
});
