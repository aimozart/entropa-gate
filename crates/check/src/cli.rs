//! The command line: `sealed`, `prereg make|verify`, `bounds`, `mutate`, `fuzz`. Exit 0 ran, 1 runner or tool error, 2 refused or usage. Output never holds case, target or key content.
use crate::sealed::{run as run_sealed, Options};
use crate::{prereg, stats, wrap, Refusal};
use std::io::Write;
use std::path::PathBuf;

const USAGE: &str = "usage: entropa-check sealed --file SET --sha HEX --out REPORT --target PATH [--arg A]... [--forecast FILE] [--prereg FILE --prereg-pubkey HEX | --no-prereg] [--runner FILE] [--anchor-ledger DIR] | prereg make --stage ID --file SET --forecast FILE --target PATH --key SEEDFILE --out PREREG [--runner FILE] [--not-key-id ID]... [--anchor-ledger DIR] | prereg verify --prereg FILE --pubkey HEX | bounds --n N --k K | mutate -- ARGS | fuzz TARGET SECONDS";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
fn flags(args: &[String], name: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| *a == name)
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect()
}
fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn read(p: &str, what: &str) -> Result<Vec<u8>, Refusal> {
    std::fs::read(p).map_err(|_| Refusal(format!("the {what} cannot be read")))
}

fn sealed(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let (Some(file), Some(sha), Some(o), Some(target)) = (
        flag(args, "--file"),
        flag(args, "--sha"),
        flag(args, "--out"),
        flag(args, "--target"),
    ) else {
        let _ = writeln!(err, "{USAGE}");
        return 2;
    };
    let prereg = match (flag(args, "--prereg"), flag(args, "--prereg-pubkey")) {
        (Some(p), Some(k)) => Some((PathBuf::from(p), k)),
        (None, None) => None,
        _ => {
            let _ = writeln!(err, "refused: --prereg and --prereg-pubkey go together");
            return 2;
        }
    };
    let opts = Options {
        file: PathBuf::from(file),
        sha,
        out: PathBuf::from(o.clone()),
        target: PathBuf::from(target),
        args: flags(args, "--arg"),
        forecast: flag(args, "--forecast").map(PathBuf::from),
        prereg,
        no_prereg: has(args, "--no-prereg"),
        runner: flag(args, "--runner").map(PathBuf::from),
        anchor_ledger: flag(args, "--anchor-ledger").map(PathBuf::from),
    };
    match run_sealed(&opts) {
        Err(e) => {
            let _ = writeln!(err, "refused: {e}");
            2
        }
        Ok(text) => {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            let t = &v["totals"];
            let _ = writeln!(out, "report written: {o}");
            let _ = writeln!(out, "cases: {}", t["cases"]);
            let _ = writeln!(out, "failed: {} of {}", t["failed"], t["cases"]);
            let _ = writeln!(out, "accepted attacks: {}", t["accepted_attacks"]);
            let _ = writeln!(
                out,
                "upper95 of the failure rate: {}",
                t["upper95_of_failure_rate"]
            );
            if v["prereg"]["matched"] == true {
                let _ = writeln!(
                    out,
                    "pre-registration: matched (stage {}), anchored: {}",
                    v["prereg"]["stage"].as_str().unwrap_or(""),
                    if v["prereg"]["anchored"] == true {
                        "yes"
                    } else {
                        "no"
                    }
                );
            } else {
                let _ = writeln!(out, "pre-registration: none given (unregistered run)");
            }
            if let Some(rows) = v["calibration"].as_array() {
                let hits = rows.iter().filter(|r| r["result"] == "hit").count();
                let _ = writeln!(out, "forecast: {hits} hit, {} miss", rows.len() - hits);
            }
            0
        }
    }
}

fn prereg_make(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let (Some(stage), Some(set), Some(fc), Some(target), Some(key), Some(o)) = (
        flag(args, "--stage"),
        flag(args, "--file"),
        flag(args, "--forecast"),
        flag(args, "--target"),
        flag(args, "--key"),
        flag(args, "--out"),
    ) else {
        let _ = writeln!(err, "{USAGE}");
        return 2;
    };
    let result = (|| -> Result<String, Refusal> {
        let (sb, fb) = (read(&set, "set file")?, read(&fc, "forecast file")?);
        crate::set::parse(&sb)?;
        crate::forecast::parse(&fb)?;
        let runner = match flag(args, "--runner") {
            Some(r) => {
                std::fs::read(r).map_err(|_| Refusal::new("the runner file cannot be read"))?
            }
            None => std::fs::read(
                std::env::current_exe()
                    .map_err(|_| Refusal::new("the runner cannot be located"))?,
            )
            .map_err(|_| Refusal::new("the runner cannot be read"))?,
        };
        let h = prereg::Hashes {
            set: crate::sha256_hex(&sb),
            forecast: crate::sha256_hex(&fb),
            runner: crate::sha256_hex(&runner),
            target: crate::sha256_hex(&read(&target, "target")?),
        };
        let record = prereg::make(
            &stage,
            &h,
            std::path::Path::new(&key),
            &flags(args, "--not-key-id"),
        )?;
        if std::path::Path::new(&o).exists() {
            return Err(Refusal::new("the output file exists or cannot be created"));
        }
        // anchor FIRST: a failed anchor leaves no pre-registration file behind (an unanchored file would look like a complete one)
        let anchored = match flag(args, "--anchor-ledger") {
            Some(dir) => Some((
                dir.clone(),
                crate::anchor::record(std::path::Path::new(&dir), &record)?,
            )),
            None => None,
        };
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&o)
            .map_err(|_| Refusal::new("the output file exists or cannot be created"))?;
        f.write_all(record.as_bytes())
            .map_err(|_| Refusal::new("the record could not be written"))?;
        let v: serde_json::Value = serde_json::from_str(&record).unwrap_or_default();
        let anchor_line = anchored.map_or(String::new(), |(d, i)| {
            format!("\nanchored in: {d} (evidence-ledger record {i})")
        });
        Ok(format!(
            "pre-registration written: {o}\npublic key: {}\nrecord sha256: {}{anchor_line}",
            v["pubkey"].as_str().unwrap_or(""),
            crate::sha256_hex(record.as_bytes())
        ))
    })();
    match result {
        Ok(text) => {
            let _ = writeln!(out, "{text}");
            0
        }
        Err(e) => {
            let _ = writeln!(err, "refused: {e}");
            2
        }
    }
}

fn prereg_verify(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let (Some(p), Some(pk)) = (flag(args, "--prereg"), flag(args, "--pubkey")) else {
        let _ = writeln!(err, "{USAGE}");
        return 2;
    };
    let text = match read(&p, "pre-registration").and_then(|b| {
        String::from_utf8(b).map_err(|_| Refusal::new("the pre-registration is not text"))
    }) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(err, "refused: {e}");
            return 2;
        }
    };
    match prereg::verify(&text, &pk) {
        Ok((stage, h)) => {
            let _ = writeln!(out, "stage: {stage}\nset_sha256: {}\nforecast_sha256: {}\nrunner_sha256: {}\ntarget_sha256: {}", h.set, h.forecast, h.runner, h.target);
            0
        }
        Err(e) => {
            let _ = writeln!(err, "refused: {e}");
            2
        }
    }
}

/// Run the command line; returns the exit code (0 ran, 1 runner or tool error, 2 refused or usage).
pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match args.first().map(String::as_str) {
        Some("sealed") => sealed(&args[1..], out, err),
        Some("prereg") => match args.get(1).map(String::as_str) {
            Some("make") => prereg_make(&args[2..], out, err),
            Some("verify") => prereg_verify(&args[2..], out, err),
            _ => {
                let _ = writeln!(err, "{USAGE}");
                2
            }
        },
        Some("bounds") => {
            let (n, k) = (
                flag(args, "--n").and_then(|x| x.parse::<usize>().ok()),
                flag(args, "--k").and_then(|x| x.parse::<usize>().ok()),
            );
            match (n, k) {
                (Some(n), Some(k)) => match stats::bounds(k, n) {
                    Ok(b) => {
                        let _ = writeln!(out, "lower95: {:.6}\nupper95: {:.6}", b.lower, b.upper);
                        0
                    }
                    Err(e) => {
                        let _ = writeln!(err, "refused: {e}");
                        2
                    }
                },
                _ => {
                    let _ = writeln!(err, "{USAGE}");
                    2
                }
            }
        }
        Some("mutate") => {
            let rest = args[1..]
                .iter()
                .skip_while(|a| *a != "--")
                .skip(1)
                .cloned()
                .collect::<Vec<_>>();
            if args.get(1).map(String::as_str) != Some("--") {
                let _ = writeln!(err, "{USAGE}");
                return 2;
            }
            wrap::mutate(&rest, err)
        }
        Some("fuzz") => match (args.get(1), args.get(2).and_then(|s| s.parse::<u64>().ok())) {
            (Some(t), Some(secs))
                if crate::name_ok(t) && (1..=86_400).contains(&secs) && args.len() == 3 =>
            {
                wrap::fuzz(t, secs, err)
            }
            _ => {
                let _ = writeln!(err, "{USAGE}");
                2
            }
        },
        _ => {
            let _ = writeln!(err, "{USAGE}");
            2
        }
    }
}
