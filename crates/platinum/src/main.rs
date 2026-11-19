//! `entropa-platinum` command line (see the library docs).
use entropa_platinum::{
    export_council, export_decisions, export_evidence, init, keys_add, keys_check, log,
    log_council, log_evidence, node_signer_for, verify, verify_council, verify_evidence, Ledger,
    Res,
};
use std::io::Read;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out: Res<String> = match (args.first().map(String::as_str), args.get(1)) {
        (Some("init"), Some(d)) => init(Path::new(d)).map(|()| "initialised".to_string()),
        (Some("log"), Some(d)) => {
            let mut s = String::new();
            let _ = std::io::stdin()
                .take(2 * 1024 * 1024 + 4096)
                .read_to_string(&mut s);
            log(Path::new(d), &s).map(|v| v.to_string())
        }
        (Some("log-evidence"), Some(d)) => {
            let mut s = String::new();
            let _ = std::io::stdin()
                .take(2 * 1024 * 1024 + 4096)
                .read_to_string(&mut s);
            log_evidence(Path::new(d), &s).map(|v| v.to_string())
        }
        (Some("log-council"), Some(d)) => {
            let mut s = String::new();
            let _ = std::io::stdin()
                .take(2 * 1024 * 1024 + 4096)
                .read_to_string(&mut s);
            log_council(Path::new(d), &s).map(|v| v.to_string())
        }
        (Some("verify-council"), Some(d)) => verify_council(Path::new(d)),
        (Some("export-council"), Some(d)) => export_council(Path::new(d)).map(|v| v.to_string()),
        (Some("verify"), Some(d)) => verify(Path::new(d)),
        (Some("verify-evidence"), Some(d)) => verify_evidence(Path::new(d)),
        (Some("export-evidence"), Some(d)) => export_evidence(Path::new(d)).map(|v| v.to_string()),
        (Some("export-decisions"), Some(d)) => export_decisions(Path::new(d)).map(|v| v.to_string()),
        (Some("pubkey"), Some(d)) => {
            let ledger = match args.get(2) {
                None => Some(Ledger::Decisions),
                Some(l) => Ledger::parse(l),
            };
            match ledger {
                Some(l) => node_signer_for(Path::new(d), l).map(|s| s.pubkey_hex()),
                None => Err("the ledger must be decisions, evidence or council".to_string()),
            }
        }
        (Some("keys-add"), Some(d)) => match args.get(2).and_then(|l| Ledger::parse(l)) {
            Some(l) => keys_add(Path::new(d), l).map(|()| format!("created {}.key", l.name())),
            None => Err("usage: keys-add DIR decisions|evidence|council".to_string()),
        },
        (Some("keys-check"), Some(d)) => keys_check(Path::new(d), args.iter().any(|a| a == "--allow-legacy")),
        (Some("serve"), Some(d)) => {
            entropa_platinum::serve::run(Path::new(d).to_path_buf()).map(|()| String::new())
        }
        _ => Err(
            "usage: entropa-platinum init|log|log-evidence|log-council|verify|verify-evidence|verify-council|export-evidence|export-council|export-decisions|pubkey [LEDGER]|keys-add DIR LEDGER|keys-check DIR [--allow-legacy]|serve DIR"
                .to_string(),
        ),
    };
    match out {
        Ok(s) => {
            // a closed pipe (for example `| head`) is not an error worth a panic
            let _ = std::io::Write::write_all(&mut std::io::stdout(), format!("{s}\n").as_bytes());
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
