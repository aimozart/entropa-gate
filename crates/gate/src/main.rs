//! `entropa-gate` binary (a thin wrapper around `entropa_gate::cli::run`).
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = entropa_gate::cli::run(
        &args,
        &mut std::io::stdin(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    std::process::exit(code);
}
