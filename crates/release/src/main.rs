//! `entropa-release keygen|sbom|sign|verify` (a stage record (not published)).
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = entropa_release::cli::run(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
