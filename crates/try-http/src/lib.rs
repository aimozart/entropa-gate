//! LS3b (a stage record (not published)): the HTTP binding of "Try the gate". This library holds the pure parts (the client key behind a proxy, the all-clients caps, the settings) and the server;
//! the decision logic stays in `entropa-try`, which this crate calls and never changes.
use std::net::{IpAddr, Ipv6Addr};

pub mod sealed;
pub mod server;
pub mod settings;

/// The key one visitor is limited by. `trusted_hops` is the number of proxies the platform puts in front of the service: the key is the entry of the (joined) `X-Forwarded-For` list
/// counted from the RIGHT (entry number `trusted_hops`), because the proxies append and everything to the left is client-supplied. With fewer entries than hops, or an entry that is not a plain
/// IP address (a port, brackets, a zone, text, nothing), or `trusted_hops == 0`, the key is the peer address. IPv6 is reduced to its /64 and IPv4-mapped IPv6 to IPv4.
pub fn client_key(xff: Option<&str>, trusted_hops: usize, peer: IpAddr) -> String {
    if trusted_hops > 0 {
        if let Some(h) = xff {
            let entries: Vec<&str> = h.split(',').map(str::trim).collect();
            if entries.len() >= trusted_hops {
                if let Ok(ip) = entries[entries.len() - trusted_hops].parse::<IpAddr>() {
                    return render(ip);
                }
            }
        }
    }
    render(peer)
}

fn render(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(m) => m.to_string(),
            None => slash64(v),
        },
    }
}

fn slash64(v: Ipv6Addr) -> String {
    let s = v.segments();
    format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
}

/// Why a request was refused by the caps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapRefusal {
    /// The closed error word (`busy` or `daily_limit`).
    pub code: &'static str,
    /// Seconds to wait (at least 1).
    pub retry_after: u64,
}

/// The all-clients caps of one instance: requests per 60-second window and requests per UTC day. Every attempt counts, refused ones too (the cap protects the instance, not the visitor).
pub struct Caps {
    global_per_min: u32,
    daily: u32,
    window_start: u64,
    window_count: u32,
    day: u64,
    day_count: u32,
    started: bool,
}

const WINDOW_SECS: u64 = 60;
const DAY_SECS: u64 = 86_400;

impl Caps {
    /// Caps of `global_per_min` requests per 60 s and `daily` per UTC day.
    pub fn new(global_per_min: u32, daily: u32) -> Caps {
        Caps {
            global_per_min,
            daily,
            window_start: 0,
            window_count: 0,
            day: 0,
            day_count: 0,
            started: false,
        }
    }

    /// Count one attempt at time `now` (seconds since the epoch); `Err` when over a cap (the daily cap is reported first).
    pub fn admit(&mut self, now: u64) -> Result<(), CapRefusal> {
        let day = now / DAY_SECS;
        if !self.started || day != self.day {
            self.day = day;
            self.day_count = 0;
        }
        if !self.started || now >= self.window_start.saturating_add(WINDOW_SECS) {
            self.window_start = now;
            self.window_count = 0;
        }
        self.started = true;
        self.day_count = self.day_count.saturating_add(1);
        self.window_count = self.window_count.saturating_add(1);
        if self.day_count > self.daily {
            return Err(CapRefusal {
                code: "daily_limit",
                retry_after: ((day + 1) * DAY_SECS).saturating_sub(now).max(1),
            });
        }
        if self.window_count > self.global_per_min {
            return Err(CapRefusal {
                code: "busy",
                retry_after: (self.window_start + WINDOW_SECS).saturating_sub(now).max(1),
            });
        }
        Ok(())
    }
}
