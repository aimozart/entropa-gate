//! The `mutate` and `fuzz` wrappers: they run ONLY a tool that is already installed (cargo-mutants, cargo-fuzz), refuse to start under 25 GB free, and cap memory at 6 GB when
//! systemd-run exists. They download and install nothing.
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const MIN_FREE_GB: u64 = 25;

/// Find an executable on the PATH of this process.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| {
            p.is_file() && std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
        })
}

/// Free space on `/` in GB, from `df -BG --output=avail /`.
fn free_gb() -> Option<u64> {
    let o = Command::new("df")
        .args(["-BG", "--output=avail", "/"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&o.stdout);
    let digits: String = text
        .lines()
        .last()?
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn start(tool: &str, cargo_args: &[String], err: &mut dyn Write) -> i32 {
    if which(tool).is_none() || which("cargo").is_none() {
        let _ = writeln!(err, "refused: {tool} (with cargo) is not installed on this machine; entropa-check does not download or install tools");
        return 2;
    }
    match free_gb() {
        Some(g) if g >= MIN_FREE_GB => {}
        Some(g) => {
            let _ = writeln!(
                err,
                "refused: only {g} GB free on / (25 GB are needed to start)"
            );
            return 2;
        }
        None => {
            let _ = writeln!(
                err,
                "refused: the free disk space could not be read (25 GB are needed to start)"
            );
            return 2;
        }
    }
    let mut cmd = if which("systemd-run").is_some() {
        let mut c = Command::new("systemd-run");
        c.args([
            "--user",
            "--scope",
            "-q",
            "-p",
            "MemoryMax=6G",
            "-p",
            "MemorySwapMax=0",
            "cargo",
        ]);
        c
    } else {
        let _ = writeln!(
            err,
            "warning: no memory cap (systemd-run is not available here)"
        );
        Command::new("cargo")
    };
    cmd.args(cargo_args);
    match cmd.status() {
        Ok(s) if s.success() => 0,
        _ => 1,
    }
}

/// `mutate -- <cargo-mutants args>`.
pub fn mutate(args: &[String], err: &mut dyn Write) -> i32 {
    let mut a = vec!["mutants".to_string()];
    a.extend(args.iter().cloned());
    start("cargo-mutants", &a, err)
}

/// `fuzz TARGET SECONDS`.
pub fn fuzz(target: &str, seconds: u64, err: &mut dyn Write) -> i32 {
    let a = vec![
        "fuzz".to_string(),
        "run".to_string(),
        target.to_string(),
        "--".to_string(),
        format!("-max_total_time={seconds}"),
    ];
    start("cargo-fuzz", &a, err)
}
