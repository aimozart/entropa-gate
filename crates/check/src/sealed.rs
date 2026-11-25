//! The one scored run: every refusal happens before the first case runs; the report is created once (create-new) and holds counts, bounds and ids only.
use crate::forecast::{self, Forecast};
use crate::report::{self, PreregInfo};
use crate::{prereg, set, target, Refusal};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Everything `sealed` needs.
#[derive(Debug, Clone)]
pub struct Options {
    /// The set file.
    pub file: PathBuf,
    /// The expected sha256 of the set file (hex).
    pub sha: String,
    /// The report file to create (must not exist).
    pub out: PathBuf,
    /// The target file.
    pub target: PathBuf,
    /// Extra arguments for the target.
    pub args: Vec<String>,
    /// The forecast file.
    pub forecast: Option<PathBuf>,
    /// A pre-registration record file and the public key it must verify under.
    pub prereg: Option<(PathBuf, String)>,
    /// Run without a pre-registration (the report says so).
    pub no_prereg: bool,
    /// The runner file whose hash is recorded (default: the running executable).
    pub runner: Option<PathBuf>,
    /// A local ledger directory that must hold the pre-registration's anchor record.
    pub anchor_ledger: Option<PathBuf>,
}

fn read_file(p: &Path, what: &str) -> Result<Vec<u8>, Refusal> {
    std::fs::read(p).map_err(|_| Refusal(format!("the {what} cannot be read")))
}

/// Run the set once and write the report; returns the report text.
pub fn run(o: &Options) -> Result<String, Refusal> {
    if o.out.exists() {
        return Err(Refusal::new(
            "a report already exists at that path; a sealed set is run once",
        ));
    }
    if std::fs::metadata(&o.file).is_ok_and(|m| m.len() > 32 * 1024 * 1024) {
        return Err(Refusal::new("the file is larger than 32 MiB"));
    }
    let set_bytes = read_file(&o.file, "set file")?;
    let set_sha = crate::sha256_hex(&set_bytes);
    if set_sha != o.sha.to_ascii_lowercase() {
        return Err(Refusal::new(
            "the sha256 of the file is not the given one; nothing was parsed",
        ));
    }
    let set = set::parse(&set_bytes)?;
    let meta =
        std::fs::metadata(&o.target).map_err(|_| Refusal::new("the target does not exist"))?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(Refusal::new("the target is not an executable file"));
    }
    let target_sha = crate::sha256_hex(&read_file(&o.target, "target")?);
    let runner_path = match &o.runner {
        Some(p) => p.clone(),
        None => {
            std::env::current_exe().map_err(|_| Refusal::new("the runner cannot be located"))?
        }
    };
    let runner_sha = crate::sha256_hex(&read_file(&runner_path, "runner")?);
    let (fc, fc_sha): (Option<Forecast>, Option<String>) = match &o.forecast {
        None => (None, None),
        Some(p) => {
            let b = read_file(p, "forecast file")?;
            let f = forecast::parse(&b)?;
            for m in &f.metrics {
                if let Some(class) = m
                    .name
                    .strip_prefix("class:")
                    .and_then(|r| r.strip_suffix(":failed_rate"))
                {
                    if !set.cases.iter().any(|c| c.class == class) {
                        return Err(Refusal::new(
                            "the forecast names a class that is not in the set",
                        ));
                    }
                }
            }
            (Some(f), Some(crate::sha256_hex(&b)))
        }
    };
    let info = match (&o.prereg, o.no_prereg) {
        (Some(_), true) => return Err(Refusal::new("a pre-registration and --no-prereg were both given")),
        (None, false) => return Err(Refusal::new("no pre-registration: give one, or state --no-prereg (the report will say the run was unregistered)")),
        (None, true) => PreregInfo::None,
        (Some((path, pubkey)), false) => {
            let fsha = fc_sha.clone().ok_or_else(|| Refusal::new("a pre-registration needs the forecast file it committed to"))?;
            let text = String::from_utf8(read_file(path, "pre-registration")?).map_err(|_| Refusal::new("the pre-registration is not text"))?;
            let (stage, h) = prereg::verify(&text, pubkey)?;
            let want = prereg::Hashes { set: set_sha.clone(), forecast: fsha, runner: runner_sha.clone(), target: target_sha.clone() };
            if h != want {
                return Err(Refusal::new("the pre-registration does not match the set, forecast, runner and target of this run"));
            }
            let anchored = match &o.anchor_ledger {
                None => false,
                Some(dir) if !dir.is_dir() => return Err(Refusal::new("the anchor ledger directory does not exist")),
                Some(dir) => crate::anchor::check(dir, &text),
            };
            PreregInfo::Matched { stage, anchored }
        }
    };
    let outcomes: Vec<target::Outcome> = set
        .cases
        .iter()
        .map(|c| target::run_case(&o.target, &o.args, c))
        .collect();
    let hashes = report::Hashes {
        set: set_sha,
        runner: runner_sha,
        target: target_sha,
        forecast: fc_sha,
    };
    let v = report::build(&set, &outcomes, &hashes, fc.as_ref(), &info);
    let text = serde_json::to_string_pretty(&v)
        .map_err(|_| Refusal::new("the report could not be written"))?
        + "\n";
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&o.out)
        .map_err(|_| {
            Refusal::new("a report already exists at that path; a sealed set is run once")
        })?;
    f.write_all(text.as_bytes())
        .map_err(|_| Refusal::new("the report could not be written"))?;
    Ok(text)
}
