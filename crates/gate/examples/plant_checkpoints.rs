//! `cargo run --example plant_checkpoints --features plant -- DIR < spec.json`: rewrite DIR/ledger/checkpoints.log from a JSON spec (a test helper for attacked ledgers; see src/plant.rs).
#![allow(clippy::print_stderr, clippy::print_stdout)]
use std::io::Read;

fn main() {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: plant_checkpoints DIR < spec.json");
        std::process::exit(2);
    };
    let mut spec = String::new();
    let _ = std::io::stdin().take(1 << 20).read_to_string(&mut spec);
    match entropa_gate::plant::plant(std::path::Path::new(&dir), &spec) {
        Ok(n) => println!("planted {n} checkpoints"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
