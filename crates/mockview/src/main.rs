//! `mockview verify LEDGER_DIR PUBLIC_KEY_HEX` (the reader's check: needs no key file) and `mockview LEDGER_DIR PUBKEY_HEX OUT_DIR [PAGE_SIZE] [--with-ledger]`: verify a mock evidence ledger and write the static bundle (and `ledger.tar` with the flag).
use entropa_mockview::{generate, Config};
use std::path::Path;

fn verify(args: &[String]) -> i32 {
    if args.len() != 4 {
        eprintln!("usage: mockview verify LEDGER_DIR PUBLIC_KEY_HEX");
        return 2;
    }
    if !Path::new(&args[2]).join("evidence-ledger").is_dir() {
        eprintln!(
            "refused: no ledger found in that directory (expected evidence-ledger/ inside it)"
        );
        return 1;
    }
    match entropa_nodecore::verify_ledger(
        Path::new(&args[2]),
        "evidence-ledger",
        entropa_ledger::Kind::is_evidence,
        &args[3],
    ) {
        Ok(t) => {
            println!("{t}");
            0
        }
        Err(e) => {
            eprintln!("refused: {e}");
            1
        }
    }
}

fn main() {
    let mut a: Vec<String> = std::env::args().collect();
    if a.get(1).map(String::as_str) == Some("verify") {
        std::process::exit(verify(&a));
    }
    let with_ledger = a.iter().skip(1).any(|x| x == "--with-ledger");
    a.retain(|x| x != "--with-ledger");
    if a.len() < 4 || a.len() > 5 {
        eprintln!("usage: mockview LEDGER_DIR PUBKEY_HEX OUT_DIR [PAGE_SIZE] [--with-ledger]");
        std::process::exit(2);
    }
    let mut cfg = Config {
        include_ledger: with_ledger,
        ..Config::default()
    };
    if let Some(n) = a.get(4).and_then(|s| s.parse::<usize>().ok()) {
        cfg.page_size = n;
    }
    match generate(Path::new(&a[1]), &a[2], Path::new(&a[3]), &cfg) {
        Ok(r) => println!(
            "OK records={} pages={} bytes={} key_id={}",
            r.records, r.pages, r.bytes, r.key_id
        ),
        Err(e) => {
            eprintln!("refused: {e}");
            std::process::exit(1);
        }
    }
}
