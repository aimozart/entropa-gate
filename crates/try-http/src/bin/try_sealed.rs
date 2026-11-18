//! `try-sealed` (LS3d): the sealed-scenario runner for `entropa-try-http` (a stage record (not published)). STUB (red phase).
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(entropa_try_http::sealed::run_cli(&args));
}
