//! The sealed-scenario runner of `entropa-try-http` (LS3d, a stage record (not published)): the file is checked against its sha256 BEFORE it is parsed, a second report is refused, and the report holds
//! counts, 95 percent bounds and scenario ids only; nothing from a scenario (bytes, strings, headers, addresses) is ever printed or stored.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};

mod exec;
mod schema;
use exec::Target;

fn refuse(msg: &str) -> i32 {
    eprintln!("refused: {msg}");
    2
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// The exact one-sided 95 percent upper bound for zero failures (1 - 0.05^(1/n)), the Wilson upper bound otherwise (the same as the EG and AT4 runners).
pub fn upper95(k: usize, n: usize) -> f64 {
    if n == 0 {
        return 1.0;
    }
    if k == 0 {
        return 1.0 - 0.05f64.powf(1.0 / n as f64);
    }
    let (p, nf, z) = (k as f64 / n as f64, n as f64, 1.645f64);
    let d = 1.0 + z * z / nf;
    ((p + z * z / (2.0 * nf) + z * (p * (1.0 - p) / nf + z * z / (4.0 * nf * nf)).sqrt()) / d)
        .min(1.0)
}

fn target_of(spec: &str) -> Result<(Target, &'static str), String> {
    if let Some(p) = spec.strip_prefix("binary:") {
        if std::fs::metadata(p).is_ok_and(|m| m.is_file()) {
            return Ok((Target::Binary(p.to_string()), "binary"));
        }
        return Err("the binary target is not an existing file".into());
    }
    if let Some(i) = spec.strip_prefix("container:") {
        let ok = !i.is_empty()
            && std::process::Command::new("docker")
                .args(["image", "inspect", i])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
        if ok {
            return Ok((Target::Container(i.to_string()), "container"));
        }
        return Err("the container image is not present locally (nothing is pulled)".into());
    }
    Err("the target must be binary:<path> or container:<image>".into())
}

#[derive(Default)]
struct Acc {
    scenarios: usize,
    failed: usize,
    accepted: usize,
    failed_ids: Vec<String>,
}

/// Run the command line; returns the exit code (0 ran, 1 runner error, 2 refused).
pub fn run_cli(args: &[String]) -> i32 {
    let (Some(file), Some(sha)) = (arg(args, "--file"), arg(args, "--sha")) else {
        return refuse("usage: try-sealed --file F --sha H (--check | --out R --target binary:PATH|container:IMAGE [--text-escapes yes|no])");
    };
    let check_only = args.iter().any(|a| a == "--check");
    let escapes = match arg(args, "--text-escapes").as_deref() {
        None | Some("no") => false,
        Some("yes") => true,
        Some(_) => return refuse("--text-escapes must be yes or no"),
    };
    let out = arg(args, "--out");
    if !check_only {
        let Some(o) = &out else {
            return refuse("--out is required");
        };
        if std::path::Path::new(o).exists() {
            return refuse("a report already exists; a sealed set is run once");
        }
    }
    if std::fs::metadata(&file).is_ok_and(|m| m.len() as usize > schema::MAX_FILE) {
        return refuse("the file is larger than 16 MiB");
    }
    let Ok(bytes) = std::fs::read(&file) else {
        return refuse("the file cannot be read");
    };
    if bytes.len() > schema::MAX_FILE {
        return refuse("the file is larger than 16 MiB");
    }
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != sha.to_ascii_lowercase() {
        return refuse("the file's sha256 is not the given one; nothing was parsed");
    }
    let set = match schema::parse(&bytes) {
        Ok(s) => s,
        Err(e) => return refuse(&e),
    };
    if check_only {
        println!("schema ok {} scenarios", set.scenarios.len());
        return 0;
    }
    let Some(spec) = arg(args, "--target") else {
        return refuse("--target is required");
    };
    let (target, kind) = match target_of(&spec) {
        Ok(t) => t,
        Err(e) => return refuse(&e),
    };
    let runner_sha = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .map(|b| hex::encode(Sha256::digest(&b)))
        .unwrap_or_default();
    // containers are stopped, never removed: a stamp keeps the names of a later run apart
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut classes: BTreeMap<String, Acc> = BTreeMap::new();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut internal: Vec<String> = Vec::new();
    for (i, sc) in set.scenarios.iter().enumerate() {
        let name = format!("ls3d-{}-{stamp}-{:04}", &actual[..8], i);
        let r = catch_unwind(AssertUnwindSafe(|| {
            exec::run_scenario(sc, &target, &name, escapes)
        }));
        let a = classes.entry(sc.class.clone()).or_default();
        a.scenarios += 1;
        let (reason, attack) = match r {
            Ok(o) => (o.reason, o.accepted_attack),
            Err(_) => {
                internal.push(sc.id.clone());
                (Some("runner_error"), false)
            }
        };
        if let Some(reason) = reason {
            a.failed += 1;
            a.failed_ids.push(sc.id.clone());
            *reasons.entry(reason.to_string()).or_insert(0) += 1;
        }
        if attack {
            a.accepted += 1;
        }
    }
    let (mut n, mut f, mut acc) = (0usize, 0usize, 0usize);
    let mut cj = serde_json::Map::new();
    for (name, a) in &classes {
        n += a.scenarios;
        f += a.failed;
        acc += a.accepted;
        cj.insert(name.clone(), json!({"scenarios": a.scenarios, "passed": a.scenarios - a.failed, "failed": a.failed, "accepted_attacks": a.accepted, "failed_ids": a.failed_ids, "upper95_of_failure_rate": upper95(a.failed, a.scenarios)}));
    }
    let report: Value = json!({
        "schema": "ls3d-report-v1", "file_sha256": actual, "runner_sha256": runner_sha, "target": kind,
        "classes": Value::Object(cj),
        "totals": {"scenarios": n, "failed": f, "accepted_attacks": acc, "upper95_of_failure_rate": upper95(f, n)},
        "reasons": reasons, "internal_error_ids": internal,
    });
    let text = match serde_json::to_string_pretty(&report) {
        Ok(t) => t + "\n",
        Err(_) => return 1,
    };
    let Some(o) = out else { return 1 };
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&o)
    {
        Ok(mut fh) => {
            if fh.write_all(text.as_bytes()).is_ok() {
                0
            } else {
                1
            }
        }
        Err(_) => refuse("a report already exists; a sealed set is run once"),
    }
}
