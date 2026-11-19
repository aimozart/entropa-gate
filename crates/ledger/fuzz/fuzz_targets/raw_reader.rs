#![no_main]
use entropa_ledger::read_raw;
use libfuzzer_sys::fuzz_target;

// The raw ledger reader never panics on hostile files: the same bytes as records.log and, split in two, as checkpoints.log. Any result is fine; a crash or hang is not.
fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!("raw-reader-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("records.log"), data);
    let half = data.len() / 2;
    let _ = std::fs::write(dir.join("checkpoints.log"), &data[half..]);
    let _ = read_raw(&dir);
});
