#![no_main]
use entropa_standards::seal;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn dir() -> &'static std::path::PathBuf {
    static D: OnceLock<std::path::PathBuf> = OnceLock::new();
    D.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("h13-seal-fuzz-{}", std::process::id()));
        std::fs::create_dir_all(d.join("v1")).unwrap();
        d
    })
}

// The corpus spec parser, and the store loader on arbitrary manifest and clause files: neither panics, and a store that opens is internally
// consistent (every clause is in the manifest).
fuzz_target!(|data: &[u8]| {
    let cut = data.first().map_or(0, |b| usize::from(*b)) * data.len() / 256;
    let (m, c) = data.split_at(cut.min(data.len()));
    let _ = seal::parse_spec(&String::from_utf8_lossy(data));
    let d = dir();
    std::fs::write(d.join("v1/manifest.json"), m).unwrap();
    std::fs::write(d.join("v1/clauses.jsonl"), c).unwrap();
    if let Ok(s) = seal::open(d, "v1") {
        assert_eq!(s.clauses.len(), s.manifest.clauses.len());
    }
    let _ = seal::list_versions(d);
});
