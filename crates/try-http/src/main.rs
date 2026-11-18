//! `entropa-try-http` (LS3b): the HTTP binding of "Try the gate". Exit 2 on a refused setting, 1 on a start-up failure. Prints one start line and, per interval, one line of status counts.
#![allow(clippy::print_stderr)]
use entropa_try_http::{server, settings};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let s = match settings::parse_args(&args, std::env::var("PORT").ok().as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("entropa-try-http: {e}");
            std::process::exit(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            eprintln!("entropa-try-http: cannot start the runtime");
            std::process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(server::run(s)) {
        eprintln!("entropa-try-http: {e}");
        std::process::exit(1);
    }
}
