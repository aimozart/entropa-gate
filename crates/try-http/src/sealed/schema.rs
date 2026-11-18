//! The schema `ls3d-sealed-v1` (a stage record (not published)): strict parsing and every limit, checked before anything runs.
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_FILE: usize = 16 * 1024 * 1024;
const MAX_SCENARIOS: usize = 2000;
const MAX_STEPS: usize = 200;
const MAX_REPEAT: usize = 5000;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_BURST: u64 = 30_000;
const MAX_PARALLEL: u64 = 64;
const MAX_SLEEP: u64 = 70_000;
const MAX_WITHIN: u64 = 120_000;
const MAX_SCENARIO_MS: u64 = 300_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub schema: String,
    pub scenarios: Vec<Scenario>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub trusted_hops: Option<usize>,
    pub allow_origin: Option<String>,
    pub global_per_min: Option<u32>,
    pub daily: Option<u32>,
    pub concurrency: Option<usize>,
    pub stats_secs: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub class: String,
    pub timeout_ms: Option<u64>,
    pub server: Option<Server>,
    #[serde(default)]
    pub secrets: Vec<String>,
    pub final_alive: Option<bool>,
    pub attack: Option<bool>,
    pub steps: Vec<Step>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub statuses: Option<Vec<u16>>,
    #[serde(default)]
    pub or_close: bool,
    #[serde(default)]
    pub headers_present: Vec<String>,
    #[serde(default)]
    pub headers_absent: Vec<String>,
    #[serde(default)]
    pub header_equals: BTreeMap<String, String>,
    pub body_equals: Option<String>,
    pub body_json_equals: Option<serde_json::Value>,
}

#[derive(Deserialize, Clone)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    Open {
        conn: String,
    },
    Send {
        conn: String,
        text: Option<String>,
        hex: Option<String>,
        repeat: Option<usize>,
        piece: Option<usize>,
        gap_ms: Option<u64>,
        pause_ms: Option<u64>,
    },
    Read {
        conn: String,
        within_ms: Option<u64>,
        expect: Option<Expect>,
        attack: Option<bool>,
    },
    Request {
        text: Option<String>,
        hex: Option<String>,
        repeat: Option<usize>,
        within_ms: Option<u64>,
        expect: Option<Expect>,
        attack: Option<bool>,
    },
    Burst {
        count: u64,
        parallel: u64,
        template: String,
        within_ms: u64,
        expect_counts: BTreeMap<String, (u64, u64)>,
        attack: Option<bool>,
    },
    Hold {
        conn: String,
        text: Option<String>,
        hex: Option<String>,
        repeat: Option<usize>,
        for_ms: Option<u64>,
    },
    Release {
        conn: String,
    },
    Sleep {
        ms: u64,
    },
    Stats {
        wait_ms: u64,
        expect_totals: BTreeMap<String, (u64, u64)>,
        attack: Option<bool>,
    },
}

/// The bytes of a `text` or `hex` field (exactly one), repeated.
pub fn bytes_of(
    text: &Option<String>,
    hex: &Option<String>,
    repeat: Option<usize>,
    escapes: bool,
) -> Result<Vec<u8>, String> {
    let one = match (text, hex) {
        (Some(t), None) if escapes => unescape(t),
        (Some(t), None) => t.as_bytes().to_vec(),
        (None, Some(h)) => hex::decode(h).map_err(|_| "a hex field is not hex".to_string())?,
        _ => return Err("exactly one of text and hex is required".into()),
    };
    let n = repeat.unwrap_or(1);
    if n == 0 || n > MAX_REPEAT {
        return Err("repeat is out of range".into());
    }
    if one.len().saturating_mul(n) > MAX_BYTES {
        return Err("a step sends more than 2 MiB".into());
    }
    Ok(one.repeat(n))
}

/// The optional second escape pass (`--text-escapes yes`): `\r \n \t \\ \" \xHH` become bytes; any other backslash stays as it is.
pub fn unescape(t: &str) -> Vec<u8> {
    let b = t.as_bytes();
    let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            let n = b[i + 1];
            let rep = match n {
                b'r' => Some(b'\r'),
                b'n' => Some(b'\n'),
                b't' => Some(b'\t'),
                b'\\' => Some(b'\\'),
                b'"' => Some(b'"'),
                _ => None,
            };
            if let Some(r) = rep {
                out.push(r);
                i += 2;
                continue;
            }
            if n == b'x' {
                if let Some(v) = t
                    .get(i + 2..i + 4)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    out.push(v);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn range(v: u64, max: u64, what: &str) -> Result<(), String> {
    if v > max {
        Err(format!("{what} is over its limit"))
    } else {
        Ok(())
    }
}

/// Parse and validate the whole file. Every error text is generic: it never repeats anything from the file.
pub fn parse(bytes: &[u8]) -> Result<File, String> {
    parse_inner(bytes)
}

fn parse_inner(bytes: &[u8]) -> Result<File, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "the file is not UTF-8".to_string())?;
    if entropa_witness::strict_json::has_duplicate_keys(text) {
        return Err("the file has a duplicate key".into());
    }
    let f: File = serde_json::from_str(text).map_err(|e| {
        // only the names of schema fields and the line are repeated, never a value from the file
        let m = e.to_string();
        if m.starts_with("unknown field")
            || m.starts_with("missing field")
            || m.starts_with("unknown variant")
        {
            format!(
                "the file does not match the schema: {} (line {})",
                m.split(" at line").next().unwrap_or(""),
                e.line()
            )
        } else {
            format!("the file does not match the schema (line {})", e.line())
        }
    })?;
    if f.schema != "ls3d-sealed-v1" {
        return Err("unknown schema".into());
    }
    if f.scenarios.len() > MAX_SCENARIOS {
        return Err("too many scenarios".into());
    }
    let mut ids = BTreeSet::new();
    for s in &f.scenarios {
        let r: Result<(), String> = (|| {
            if !ids.insert(s.id.clone()) {
                return Err("a scenario id is used twice".into());
            }
            if s.steps.len() > MAX_STEPS {
                return Err("too many steps in a scenario".into());
            }
            range(s.timeout_ms.unwrap_or(0), MAX_SCENARIO_MS, "timeout_ms")?;
            let mut open: BTreeSet<&str> = BTreeSet::new();
            for st in &s.steps {
                match st {
                    Step::Open { conn } => {
                        open.insert(conn);
                    }
                    Step::Send {
                        conn,
                        text,
                        hex,
                        repeat,
                        piece,
                        gap_ms,
                        pause_ms,
                    } => {
                        bytes_of(text, hex, *repeat, false)?;
                        if *piece == Some(0) {
                            return Err("piece must be at least 1".into());
                        }
                        range(gap_ms.unwrap_or(0), MAX_SLEEP, "gap_ms")?;
                        range(pause_ms.unwrap_or(0), MAX_SLEEP, "pause_ms")?;
                        open.insert(conn);
                    }
                    Step::Hold {
                        conn,
                        text,
                        hex,
                        repeat,
                        for_ms,
                    } => {
                        bytes_of(text, hex, *repeat, false)?;
                        range(for_ms.unwrap_or(0), MAX_SLEEP, "for_ms")?;
                        open.insert(conn);
                    }
                    Step::Read {
                        conn, within_ms, ..
                    } => {
                        range(within_ms.unwrap_or(0), MAX_WITHIN, "within_ms")?;
                        if !open.contains(conn.as_str()) {
                            return Err("a step uses a connection that was never opened".into());
                        }
                    }
                    Step::Release { conn } => {
                        if !open.contains(conn.as_str()) {
                            return Err("a step uses a connection that was never opened".into());
                        }
                    }
                    Step::Request {
                        text,
                        hex,
                        repeat,
                        within_ms,
                        ..
                    } => {
                        bytes_of(text, hex, *repeat, false)?;
                        range(within_ms.unwrap_or(0), MAX_WITHIN, "within_ms")?;
                    }
                    Step::Burst {
                        count,
                        parallel,
                        within_ms,
                        ..
                    } => {
                        range(*count, MAX_BURST, "count")?;
                        if *parallel == 0 {
                            return Err("parallel must be at least 1".into());
                        }
                        range(*parallel, MAX_PARALLEL, "parallel")?;
                        range(*within_ms, MAX_WITHIN, "within_ms")?;
                    }
                    Step::Sleep { ms } => range(*ms, MAX_SLEEP, "ms")?,
                    Step::Stats { wait_ms, .. } => range(*wait_ms, MAX_SLEEP, "wait_ms")?,
                }
            }
            if s.steps
                .iter()
                .filter_map(|st| {
                    if let Step::Burst { count, .. } = st {
                        Some(*count)
                    } else {
                        None
                    }
                })
                .sum::<u64>()
                > MAX_BURST
            {
                return Err("more than 30,000 burst requests in a scenario".into());
            }

            Ok(())
        })();
        r.map_err(|e| format!("scenario {}: {e}", s.id))?;
    }
    Ok(f)
}
