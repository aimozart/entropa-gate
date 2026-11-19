//! Shared helpers: scratch directories, executable shell-script targets, set files. Synthetic data only.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn scratch(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("chk-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
pub fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}
pub fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    p
}
pub fn sha(bytes: &[u8]) -> String {
    entropa_check::sha256_hex(bytes)
}
/// A target that blocks input containing "BAD" and allows everything else.
pub const GUARD: &str = r#"in=$(cat); case "$in" in *BAD*) echo block;; *) echo allow;; esac"#;
