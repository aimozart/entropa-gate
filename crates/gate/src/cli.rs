//! The command line: `init --dir D`, `record --dir D` (one JSON request on stdin), `verify --dir D`, `status --dir D [--config C]`.
use crate::config::Config;
use crate::{keys, node, GateError};
use std::io::{Read, Write};
use std::path::PathBuf;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Run the command line; returns the exit code (0 ok, 1 refused or failed, 2 usage). Errors are short and never echo input.
pub fn run(args: &[String], stdin: &mut dyn Read, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let usage = |err: &mut dyn Write| {
        let _ = writeln!(err, "usage: entropa-gate init|record|verify|status|explorer --dir DIR [--config FILE] [--out DIR]   (record reads one JSON request on stdin)");
        2
    };
    if args.first().map(String::as_str) == Some("licence") {
        return licence_cmd(args, out, err);
    }
    let (Some(cmd), Some(dir)) = (args.first(), flag(args, "--dir")) else {
        return usage(err);
    };
    let dir = PathBuf::from(dir);
    let result: Result<String, GateError> = match cmd.as_str() {
        "init" => keys::init(&dir).map(|()| "initialised".to_string()),
        "record" => {
            let mut buf = Vec::new();
            let _ = stdin
                .take(node::MAX_REQUEST_BYTES as u64 + 1)
                .read_to_end(&mut buf);
            match String::from_utf8(buf) {
                Ok(s) => node::record(&dir, &s).map(|r| r.to_json()),
                Err(_) => Err(GateError::Invalid("request is not UTF-8".into())),
            }
        }
        "verify" => node::verify(&dir),
        "explorer" => explorer_cmd(args, &dir),
        "status" => node::status(&dir).and_then(|s| {
            let org = match flag(args, "--config") {
                Some(p) => {
                    let t = std::fs::read_to_string(&p)
                        .map_err(|_| GateError::Io("cannot read the config".into()))?;
                    format!("org: {}\n", Config::parse(&t)?.org_name)
                }
                None => String::new(),
            };
            Ok(format!(
                "{org}records: {}\ncheckpoints: {}\nkey_id: {}\npubkey: {}",
                s.records, s.checkpoints, s.key_id, s.pubkey
            ))
        }),
        _ => return usage(err),
    };
    match result {
        Ok(s) => {
            let _ = writeln!(out, "{s}");
            0
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

fn explorer_cmd(args: &[String], dir: &std::path::Path) -> Result<String, GateError> {
    let cfg_path = flag(args, "--config")
        .ok_or_else(|| GateError::Invalid("explorer needs --config FILE".into()))?;
    let out =
        flag(args, "--out").ok_or_else(|| GateError::Invalid("explorer needs --out DIR".into()))?;
    let text = std::fs::read_to_string(&cfg_path)
        .map_err(|_| GateError::Io("cannot read the config".into()))?;
    let cfg = Config::parse(&text)?;
    let g = crate::explorer::generate(dir, &cfg, std::path::Path::new(&out))?;
    Ok(format!(
        "verified: {}\nrecords shown: {}\nfiles: {}",
        g.verified,
        g.shown,
        g.files.join(", ")
    ))
}

/// The verification key built into this binary at compile time (`ENTROPA_GATE_LICENCE_PUBKEY`); `None` in a build that did not set it.
const EMBEDDED_PUBKEY: Option<&str> = option_env!("ENTROPA_GATE_LICENCE_PUBKEY");

fn licence_cmd(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    use crate::licence::{check, Policy, DEFAULT_TOLERANCE_SECS};
    if args.get(1).map(String::as_str) != Some("check") {
        let _ = writeln!(err, "usage: entropa-gate licence check --file FILE [--pubkey-file FILE] [--require ENTITLEMENT]");
        return 2;
    }
    let Some(file) = flag(args, "--file") else {
        let _ = writeln!(err, "licence: --file FILE is required");
        return 2;
    };
    let (key, source) = match flag(args, "--pubkey-file") {
        Some(p) => match std::fs::read_to_string(&p) {
            Ok(t) => (
                Some(t.trim().to_string()),
                "file (not the key built into this binary)",
            ),
            Err(_) => (None, "file"),
        },
        None => (EMBEDDED_PUBKEY.map(str::to_string), "build"),
    };
    let Some(key) = key.filter(|k| !k.is_empty()) else {
        let _ = writeln!(
            err,
            "licence: no verification key (this build has none embedded; pass --pubkey-file)"
        );
        return 1;
    };
    let Ok(bytes) = std::fs::read(&file) else {
        let _ = writeln!(err, "licence: cannot read the licence file");
        return 1;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let policy = Policy {
        now,
        tolerance_secs: DEFAULT_TOLERANCE_SECS,
        require: flag(args, "--require"),
    };
    match check(&bytes, &key, &policy) {
        Ok(c) => {
            let _ = writeln!(
                out,
                "licence: OK\ncustomer: {}\nentitlements: {}\nvalid: {} to {} (unix seconds)\nbuild: {}\nclock tolerance: {} h\nkey source: {source}",
                c.customer_id,
                c.entitlements.join(", "),
                c.not_before,
                c.expiry,
                c.build_id,
                DEFAULT_TOLERANCE_SECS / 3600
            );
            0
        }
        Err(d) => {
            let _ = writeln!(err, "licence: refused ({})", d.as_str());
            1
        }
    }
}
