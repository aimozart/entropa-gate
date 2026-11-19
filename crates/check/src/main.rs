//! `entropa-check`: the sealed-run discipline for your own guard rules (a stage record (not published)).
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = entropa_check::cli::run(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
