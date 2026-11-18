//! The per-client static explorer: a small site (HTML, CSS, one JS file) generated from the client's own ledger and config. It makes no external
//! request, escapes every value, shows the result of the offline verifier computed AT GENERATION TIME (a tampered copy shows FAIL), and does not
//! verify anything in the browser. No wall clock is read: the same inputs give the same bytes.
use crate::config::Config;
use crate::{node, GateError, Res};
use entropa_core::transparency_log::decode_record;
use entropa_ledger::{decode_event, plain_english, FileStore, LedgerStore};
use std::fmt::Write as _;
use std::path::Path;

/// The marker file that says a directory is a previous output of this command.
pub const MARKER: &str = ".entropa-explorer";
const MAX_LOGO_BYTES: u64 = 100 * 1024;

/// What `generate` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    /// The offline verifier accepted the ledger at generation time.
    pub verified: bool,
    /// Records on disk that were shown (0 when the ledger failed verification).
    pub shown: u64,
    /// File names written (relative to the output directory), sorted.
    pub files: Vec<String>,
}

fn io<T>(m: &str) -> Res<T> {
    Err(GateError::Io(m.to_string()))
}

/// Escape one value for HTML text or a double-quoted attribute. Bidirectional controls and NUL become U+FFFD.
pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            '`' => o.push_str("&#96;"),
            '\u{0}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200e}'
            | '\u{200f}' => o.push('\u{fffd}'),
            c => o.push(c),
        }
    }
    o
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS UTC` (civil date from days, no library).
fn utc(ts: u64) -> String {
    let (days, rem) = ((ts / 86400) as i64, ts % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

const CSS: &str = ":root{--accent:ACCENT}\n\
body{font-family:system-ui,sans-serif;margin:0;color:#1b1b1b;background:#fafafa}\n\
header,main,footer{max-width:68rem;margin:0 auto;padding:1rem}\n\
header{display:flex;align-items:center;gap:1rem;border-bottom:4px solid var(--accent)}\n\
header img{height:3rem}\n\
h1{font-size:1.5rem;margin:0}\n\
.status{padding:1rem;border-radius:.4rem;margin:1rem 0;border:2px solid}\n\
.status-ok{background:#e8f5e9;border-color:#2e7d32}\n\
.status-fail{background:#ffebee;border-color:#b71c1c}\n\
.status strong{font-size:1.2rem}\n\
table{border-collapse:collapse;width:100%;font-size:.9rem}\n\
th,td{border-bottom:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}\n\
th{background:#eee}\n\
code{word-break:break-all;font-size:.8rem}\n\
input{padding:.4rem;margin:.5rem 0;width:18rem;max-width:100%}\n\
[hidden]{display:none}\n";

const JS: &str = "(function () {\n\
  var f = document.getElementById('filter');\n\
  if (!f) { return; }\n\
  var rows = document.querySelectorAll('tr[data-label]');\n\
  f.addEventListener('input', function () {\n\
    var q = f.value.toLowerCase();\n\
    rows.forEach(function (r) { r.hidden = q !== '' && r.textContent.toLowerCase().indexOf(q) < 0; });\n\
  });\n\
})();\n";

fn write(out: &Path, name: &str, bytes: &[u8]) -> Res<()> {
    std::fs::write(out.join(name), bytes).map_err(|_| GateError::Io(format!("cannot write {name}")))
}

/// Generate the site into `out` (created if missing). Refuses a non-empty directory that is not a previous output of this command.
pub fn generate(dir: &Path, cfg: &Config, out: &Path) -> Res<Generated> {
    // logo first, so a bad logo changes nothing
    let logo = match &cfg.logo_file {
        None => None,
        Some(p) => {
            let path = Path::new(p);
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            if !matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "svg") {
                return io("the logo must be a png, jpg, gif or svg file");
            }
            let meta = std::fs::metadata(path)
                .map_err(|_| GateError::Io("cannot read the logo file".into()))?;
            if !meta.is_file() || meta.len() > MAX_LOGO_BYTES {
                return io("the logo must be a file of at most 100 KiB");
            }
            let bytes = std::fs::read(path)
                .map_err(|_| GateError::Io("cannot read the logo file".into()))?;
            Some((format!("logo.{ext}"), bytes))
        }
    };
    if out.exists() {
        let empty = std::fs::read_dir(out)
            .map_err(|_| GateError::Io("cannot read the output directory".into()))?
            .next()
            .is_none();
        if !empty && !out.join(MARKER).exists() {
            return io("the output directory is not empty and is not an explorer output");
        }
    }
    // the offline verifier, at generation time: a tamper (Verify error) is shown, any other problem refuses
    let (verified, line) = match node::verify(dir) {
        Ok(l) => (true, l),
        Err(GateError::Verify(m)) => (false, m),
        Err(e) => return Err(e),
    };
    let mut rows = String::new();
    let mut cps = String::new();
    let mut shown = 0u64;
    if verified {
        let store = FileStore::open(&dir.join("ledger"))
            .map_err(|_| GateError::Io("the ledger does not open".into()))?;
        for i in 0..store.len() {
            let rec = store
                .record(i)
                .ok_or_else(|| GateError::Io("a record is missing".into()))?;
            let (payload, _) = decode_record(&rec)
                .map_err(|_| GateError::Verify("a record is undecodable".into()))?;
            let ev = decode_event(&payload)
                .map_err(|_| GateError::Verify("an event is undecodable".into()))?;
            let f = &ev.fields;
            let _ = writeln!(
                rows,
                "<tr data-label=\"{l}\" data-decision=\"{d}\"><td>{i}</td><td>{t}</td><td>{l}</td><td>{d}</td><td>{r}</td><td><code>{h}</code></td><td><code>{k}</code></td><td>{p}</td></tr>",
                l = escape(f.label.as_str()),
                d = escape(f.decision.as_str()),
                r = escape(f.reason.as_str()),
                t = escape(&utc(f.ts)),
                h = escape(&f.subject_hash),
                k = escape(&f.key_id),
                p = escape(&plain_english(f)),
            );
            shown += 1;
        }
        for (n, cp) in store.checkpoints().iter().enumerate() {
            let _ = writeln!(
                cps,
                "<tr><td>{n}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                cp.size,
                escape(&utc(cp.timestamp)),
                escape(&hex_root(&cp.root))
            );
        }
    }
    let org = escape(&cfg.org_name);
    let mut h = String::new();
    h.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    let _ = write!(h, "<title>{org} audit explorer</title><link rel=\"stylesheet\" href=\"style.css\"></head><body>\n<header>");
    if let Some((name, _)) = &logo {
        let _ = write!(h, "<img src=\"{}\" alt=\"{org} logo\">", escape(name));
    }
    let _ = write!(h, "<h1>{org}</h1></header>\n<main>\n");
    if verified {
        let _ = write!(
            h,
            "<section class=\"status status-ok\"><strong>OK</strong> <span>{}</span>",
            escape(&line)
        );
    } else {
        let _ = write!(
            h,
            "<section class=\"status status-fail\"><strong>FAIL</strong> <span>{}</span>",
            escape(&line)
        );
    }
    h.push_str("<p>This result was checked by the offline verifier when this page was generated; this page does not verify anything in your browser. A ledger that changes after generation is not reflected here.</p></section>\n");
    if verified {
        h.push_str("<h2>Records</h2><input type=\"text\" id=\"filter\" placeholder=\"filter records\" aria-label=\"filter records\">\n<table><thead><tr><th>#</th><th>Time</th><th>Label</th><th>Decision</th><th>Reason</th><th>Subject hash</th><th>Key id</th><th>Meaning</th></tr></thead><tbody>\n");
        h.push_str(&rows);
        h.push_str("</tbody></table>\n<h2>Checkpoints</h2><table><thead><tr><th>#</th><th>Records</th><th>Time</th><th>Merkle root</th></tr></thead><tbody>\n");
        h.push_str(&cps);
        h.push_str("</tbody></table>\n");
    } else {
        h.push_str("<p>The records of a ledger that failed verification are not shown.</p>\n");
    }
    if !cfg.tiers.is_empty() {
        h.push_str("<h2>Tiers</h2><ul>");
        for t in &cfg.tiers {
            let _ = write!(h, "<li>{}</li>", escape(t));
        }
        h.push_str("</ul>\n");
    }
    if !cfg.witnesses.is_empty() {
        h.push_str("<h2>Witnesses the client allows</h2><ul>");
        for w in &cfg.witnesses {
            let _ = write!(h, "<li><code>{}</code></li>", escape(w));
        }
        h.push_str("</ul>\n");
    }
    h.push_str("</main>\n<footer><p>Generated by entropa-gate. Tamper-evident, checked by the offline verifier; no claim is made about anything the ledger does not record.</p></footer>\n<script src=\"app.js\"></script></body></html>\n");

    std::fs::create_dir_all(out)
        .map_err(|_| GateError::Io("cannot create the output directory".into()))?;
    write(out, MARKER, b"entropa-gate explorer output\n")?;
    write(out, "index.html", h.as_bytes())?;
    write(
        out,
        "style.css",
        CSS.replace("ACCENT", &cfg.accent_color).as_bytes(),
    )?;
    write(out, "app.js", JS.as_bytes())?;
    let mut files = vec![
        "app.js".to_string(),
        "index.html".to_string(),
        "style.css".to_string(),
    ];
    if let Some((name, bytes)) = &logo {
        write(out, name, bytes)?;
        files.push(name.clone());
    }
    files.sort();
    Ok(Generated {
        verified,
        shown,
        files,
    })
}

fn hex_root(root: &[u8; 32]) -> String {
    root.iter().map(|b| format!("{b:02x}")).collect()
}
