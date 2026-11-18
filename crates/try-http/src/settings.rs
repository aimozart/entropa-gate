//! The command-line settings of `entropa-try-http`. `--trusted-hops` and `--allow-origin` have NO default: the binary refuses to start without them (a stage record (not published) section 2 and 5).
use std::net::SocketAddr;

/// What the binary was told to do.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The address to listen on.
    pub listen: SocketAddr,
    /// The number of proxies in front of the service.
    pub trusted_hops: usize,
    /// The single origin that may call the endpoint from a page.
    pub allow_origin: String,
    /// All clients together, per 60 s.
    pub global_per_min: u32,
    /// All clients together, per UTC day.
    pub daily: u32,
    /// Concurrent requests.
    pub concurrency: usize,
    /// Seconds between two status-count lines.
    pub stats_secs: u64,
}

fn number<T: std::str::FromStr>(name: &str, v: &str) -> Result<T, String> {
    v.parse()
        .map_err(|_| format!("{name} must be a whole number"))
}

/// Parse the arguments (without the program name). The error text never contains the value that was given.
pub fn parse_args(args: &[String], port_env: Option<&str>) -> Result<Settings, String> {
    let (mut listen, mut hops, mut origin) = (None, None, None);
    let (mut global, mut daily, mut conc, mut stats) = (600u32, 20_000u32, 8usize, 60u64);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let v = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--listen" => {
                listen = Some(
                    v.parse::<SocketAddr>()
                        .map_err(|_| "--listen must be ADDRESS:PORT".to_string())?,
                )
            }
            "--trusted-hops" => hops = Some(number::<usize>("--trusted-hops", v)?),
            "--allow-origin" => origin = Some(v.clone()),
            "--global-per-min" => global = number("--global-per-min", v)?,
            "--daily" => daily = number("--daily", v)?,
            "--concurrency" => conc = number("--concurrency", v)?,
            "--stats-secs" => stats = number("--stats-secs", v)?,
            other => return Err(format!("unknown option {other}")),
        }
    }
    let trusted_hops = hops.ok_or("--trusted-hops is required (no default: it is the number of proxies in front of the service)")?;
    let allow_origin = origin.ok_or("--allow-origin is required (exactly one origin)")?;
    // exactly one origin: a scheme, a non-empty host (a port is allowed), nothing else (no star, no list, no path, no blank, only printable ASCII)
    let host = allow_origin
        .strip_prefix("https://")
        .or_else(|| allow_origin.strip_prefix("http://"));
    if !host.is_some_and(|h| !h.is_empty() && !h.contains('/'))
        || allow_origin.contains(['*', ',', ' ', '\t'])
        || !allow_origin.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err("--allow-origin must be exactly one origin such as https://host (no star, no list, no path)".into());
    }
    if conc == 0 || stats == 0 {
        return Err("--concurrency and --stats-secs must be at least 1".into());
    }
    let listen = match listen {
        Some(l) => l,
        None => {
            let port: u16 = port_env.and_then(|p| p.parse().ok()).unwrap_or(8080);
            SocketAddr::from(([0, 0, 0, 0], port))
        }
    };
    Ok(Settings {
        listen,
        trusted_hops,
        allow_origin,
        global_per_min: global,
        daily,
        concurrency: conc,
        stats_secs: stats,
    })
}
