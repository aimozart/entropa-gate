//! `egress-eval`: DEV evaluation, the clean-clause cost measurement, and the sealed runner (`heldout-eg`). Reads files, writes a report. No
//! network, no clock. The sealed runner checks the set's SHA-256 before parsing it and refuses a second run.
use entropa_egress::eval::{
    clause_cost, load_policy, policy_from_extra, report, run_cases_with, Pipeline,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1).cloned())
}
fn read_cases(p: &Path) -> Result<Vec<Value>, String> {
    let t = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    t.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| e.to_string()))
        .collect()
}
fn clauses(store: &Path, version: &str) -> Result<Vec<(String, String, String)>, String> {
    let t = std::fs::read_to_string(store.join(version).join("clauses.jsonl"))
        .map_err(|e| e.to_string())?;
    t.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l).map_err(|e| e.to_string())?;
            Ok((
                v["standard"].as_str().unwrap_or("").to_string(),
                v["id"].as_str().unwrap_or("").to_string(),
                v["text"].as_str().unwrap_or("").to_string(),
            ))
        })
        .collect()
}
fn policy(a: &[String], dir: &Path) -> Result<entropa_egress::policy::Policy, String> {
    match arg(a, "--policy") {
        Some(p) => load_policy(&std::fs::read_to_string(p).map_err(|e| e.to_string())?),
        None => {
            let extra: Value = serde_json::from_str(
                &std::fs::read_to_string(dir.join("eg_policy_extra.json"))
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            load_policy(&policy_from_extra(&extra))
        }
    }
}

/// `--pipeline v1|v2` (default v1: the guard as sealed in round 5).
fn pipeline(a: &[String]) -> Result<Pipeline, String> {
    match arg(a, "--pipeline").as_deref() {
        None | Some("v1") => Ok(Pipeline::V1),
        Some("v2") => Ok(Pipeline::V2),
        Some(_) => Err("--pipeline must be v1 or v2".to_string()),
    }
}

fn run(a: &[String]) -> Result<i32, String> {
    match a.first().map(String::as_str) {
        Some("dev-eval") => {
            let dir = PathBuf::from(arg(a, "--dir").ok_or("--dir")?);
            let pol = policy(a, &dir)?;
            let mut cases = Vec::new();
            for c in [
                "secrets",
                "personal",
                "terms",
                "clean",
                "destination",
                "abuse",
            ] {
                cases.extend(read_cases(&dir.join(format!("eg_{c}.jsonl")))?);
            }
            let mut rep = report(&run_cases_with(&cases, &pol, pipeline(a)?)?);
            if let (Some(store), Some(ver)) = (arg(a, "--store"), arg(a, "--version")) {
                rep["standards_clauses"] = clause_cost(&clauses(Path::new(&store), &ver)?, &pol);
            }
            let out = serde_json::to_string_pretty(&rep).map_err(|e| e.to_string())?;
            match arg(a, "--out") {
                Some(p) => std::fs::write(p, out + "\n").map_err(|e| e.to_string())?,
                None => println!("{out}"),
            }
            Ok(0)
        }
        Some("heldout-eg") => {
            let file = PathBuf::from(arg(a, "--file").ok_or("--file")?);
            let sha = arg(a, "--sha").ok_or("--sha")?;
            let out = PathBuf::from(arg(a, "--out").ok_or("--out")?);
            if out.exists() {
                eprintln!("refused: a report already exists; a sealed set is run once");
                return Ok(3);
            }
            let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
            if hex::encode(Sha256::digest(&bytes)) != sha {
                eprintln!("refused: the file's sha256 is not the given one; nothing was parsed");
                return Ok(3);
            }
            let set: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            let rep = entropa_egress::sealed::run_set_with(&set, &sha, pipeline(a)?)?;
            std::fs::write(
                &out,
                serde_json::to_string_pretty(&rep).map_err(|e| e.to_string())? + "\n",
            )
            .map_err(|e| e.to_string())?;
            Ok(0)
        }
        Some("latency") => {
            let n: usize = arg(a, "--n").and_then(|x| x.parse().ok()).unwrap_or(2000);
            let out = serde_json::to_string_pretty(&entropa_egress::eval::latency(n)?)
                .map_err(|e| e.to_string())?;
            match arg(a, "--out") {
                Some(p) => std::fs::write(p, out + "\n").map_err(|e| e.to_string())?,
                None => println!("{out}"),
            }
            Ok(0)
        }
        Some("explain") => {
            // local diagnosis only: which detector and view matched, with a snippet of at most 24 characters; never run on licensed text
            let (store, ver) = (
                arg(a, "--store").ok_or("--store")?,
                arg(a, "--version").ok_or("--version")?,
            );
            let want: Vec<String> = arg(a, "--ids")
                .unwrap_or_default()
                .split(',')
                .map(String::from)
                .collect();
            for (std, id, text) in clauses(Path::new(&store), &ver)? {
                if std == "PCI-DSS" || !want.contains(&format!("{std}:{id}")) {
                    continue;
                }
                let cfg = entropa_egress::detect::DetectCfg::default();
                let f = entropa_egress::views::fold(&text);
                let s = entropa_egress::views::strip(&text);
                for (kind, t) in [
                    (entropa_egress::detect::ViewKind::Raw, text.clone()),
                    (entropa_egress::detect::ViewKind::Folded, f.text),
                    (entropa_egress::detect::ViewKind::Stripped, s.text),
                ] {
                    for h in entropa_egress::detect::scan_kind(&t, kind, &cfg) {
                        let snip: String = t[h.start..h.end].chars().take(24).collect();
                        println!("{std}:{id} {} {} {snip}", h.det.as_str(), kind.as_str());
                    }
                }
            }
            Ok(0)
        }
        Some("make-policy") => {
            let extra: Value = serde_json::from_str(
                &std::fs::read_to_string(arg(a, "--extra").ok_or("--extra")?)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let text = policy_from_extra(&extra);
            std::fs::write(arg(a, "--out").ok_or("--out")?, text + "\n")
                .map_err(|e| e.to_string())?;
            Ok(0)
        }
        _ => {
            eprintln!("usage: egress-eval dev-eval --dir D [--policy P] [--store S --version V] [--out F] | heldout-eg --file F --sha H --out R [--policy P] [--store S --version V] | make-policy --extra E --out F | latency [--n N] [--out F]");
            Ok(2)
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match run(&a) {
        Ok(c) => std::process::exit(c),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
