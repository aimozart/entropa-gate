//! LS2 (a stage record (not published)): a STATIC explorer bundle from a mock evidence ledger. Nothing is written unless the ledger verifies and the mock marker is present.
use entropa_core::merkle::leaf_hash;
use entropa_core::transparency_log::decode_record;
use entropa_ledger::{decode_event, plain_english, FileStore, Kind, LedgerStore};
use serde_json::{json, Value};
use std::path::Path;

/// The label every page and every JSON file carries.
pub const LABEL: &str = "mock data, real signed records";

/// Generator settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Records per JSON page.
    pub page_size: usize,
    /// Also write `ledger.tar` (the mock ledger's marker, records and checkpoints; never a key file).
    pub include_ledger: bool,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            page_size: 200,
            include_ledger: false,
        }
    }
}

/// Why no bundle was written (closed list; never echoes ledger or file text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewError {
    /// The ledger failed offline verification.
    NotVerified(String),
    /// `MOCK-DATA.txt` is missing, too large, or its first line is not the label.
    NoMockMarker(String),
    /// The ledger has no records.
    Empty,
    /// A file operation failed.
    Io(String),
}
impl std::fmt::Display for ViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ViewError {}

/// What `generate` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Records rendered.
    pub records: usize,
    /// JSON pages written.
    pub pages: usize,
    /// Total bytes of every file written.
    pub bytes: u64,
    /// The signer's key id (16 hex).
    pub key_id: String,
}

const INDEX_HTML: &str = include_str!("../assets/index.html");
const STYLE_CSS: &str = include_str!("../assets/style.css");
const APP_JS: &str = include_str!("../assets/app.js");
const MAX_MARKER_BYTES: usize = 4096;
const TAR_NAME: &str = "ledger.tar";
const TAR_HOW_TO: &str = "Download ledger.tar, extract it (tar -xf ledger.tar -C DIR), then run entropa-mockview verify DIR PUBLIC_KEY_HEX with the public key shown above.";
const VERIFY_COMMAND: &str = "entropa-mockview verify <DIR> <PUBLIC_KEY_HEX>";

const WHAT_IS_MOCK: [&str; 3] = [
    "The traffic: every decision comes from a seeded generator, not from a person or a customer.",
    "The signing key: a throwaway key made for this ledger directory, not a production key.",
    "Nothing here is production data or customer data.",
];
const WHAT_IS_REAL: [&str; 3] = [
    "The engine: the gate, the egress guard and change control ran for every decision.",
    "The signatures: every record and checkpoint is signed (ML-DSA-65) and was verified offline before this page was written.",
    "The ledger: an append-only Merkle log, the same code as the public node.",
];
const NOT_CLAIMED: &str =
    "This page does not verify anything in your browser. Run the command above on your own copy of the ledger.";

fn io(what: &str) -> ViewError {
    ViewError::Io(what.to_string())
}

/// JSON text that is safe inside any HTML context: the three markup characters can only occur inside strings, where an escape is the same value.
fn json_text(v: &Value) -> Result<String, ViewError> {
    let t = serde_json::to_string(v).map_err(|_| io("json"))?;
    Ok(t.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026"))
}

fn read_marker(dir: &Path) -> Result<Vec<String>, ViewError> {
    let bad = |m: &str| ViewError::NoMockMarker(m.to_string());
    let b =
        std::fs::read(dir.join("MOCK-DATA.txt")).map_err(|_| bad("MOCK-DATA.txt is missing"))?;
    if b.len() > MAX_MARKER_BYTES {
        return Err(bad("MOCK-DATA.txt is too large"));
    }
    let t = String::from_utf8(b).map_err(|_| bad("MOCK-DATA.txt is not UTF-8"))?;
    let mut lines = t.lines();
    if lines.next() != Some(LABEL) {
        return Err(bad("the first line is not the label"));
    }
    Ok(lines
        .map(str::to_string)
        .filter(|l| !l.trim().is_empty())
        .collect())
}

/// A minimal deterministic ustar archive (mode 0644, owner 0, mtime 0) of the given (name, bytes) entries.
fn ustar(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, ViewError> {
    let mut out = Vec::new();
    for (name, data) in entries {
        if name.len() > 100 {
            return Err(io("tar name too long"));
        }
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let put = |h: &mut [u8; 512], at: usize, text: &str| {
            h[at..at + text.len()].copy_from_slice(text.as_bytes())
        };
        put(&mut h, 100, "0000644\0");
        put(&mut h, 108, "0000000\0");
        put(&mut h, 116, "0000000\0");
        put(&mut h, 124, &format!("{:011o}\0", data.len()));
        put(&mut h, 136, "00000000000\0");
        h[148..156].copy_from_slice(b"        ");
        h[156] = b'0';
        put(&mut h, 257, "ustar\0");
        put(&mut h, 263, "00");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        put(&mut h, 148, &format!("{sum:06o}\0 "));
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.extend(std::iter::repeat_n(0u8, (512 - data.len() % 512) % 512));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    Ok(out)
}

fn key_id(pubkey_hex: &str) -> String {
    match hex::decode(pubkey_hex) {
        Ok(b) if !b.is_empty() => hex::encode(&blake3::hash(&b).as_bytes()[..8]),
        _ => String::new(),
    }
}

/// Verify the evidence ledger of `ledger_dir` under `pubkey_hex`, check the mock marker, and write the static bundle into `out_dir`.
pub fn generate(
    ledger_dir: &Path,
    pubkey_hex: &str,
    out_dir: &Path,
    cfg: &Config,
) -> Result<Report, ViewError> {
    let notes = read_marker(ledger_dir)?;
    entropa_nodecore::verify_ledger(ledger_dir, "evidence-ledger", Kind::is_evidence, pubkey_hex)
        .map_err(|e| ViewError::NotVerified(e.to_string()))?;
    let store = FileStore::open_read_only(&ledger_dir.join("evidence-ledger"))
        .map_err(|_| ViewError::NotVerified("the ledger does not open".into()))?;
    let n = store.len();
    if n == 0 {
        return Err(ViewError::Empty);
    }
    let size = cfg.page_size.max(1);
    let cps = store.checkpoints();
    let mut rows = Vec::with_capacity(n);
    for i in 0..n {
        let rec = store.record(i).ok_or_else(|| io("record missing"))?;
        let (payload, _) = decode_record(&rec).map_err(|_| io("undecodable record"))?;
        let ev = decode_event(&payload).map_err(|_| io("undecodable event"))?;
        let f = &ev.fields;
        let e = f
            .evidence
            .as_ref()
            .ok_or_else(|| io("not an evidence record"))?;
        let cp = cps
            .iter()
            .find(|c| c.size > i)
            .ok_or_else(|| io("no checkpoint covers a record"))?;
        rows.push(json!({
            "index": i, "ts": f.ts, "plain": plain_english(f), "kind": f.kind.as_str(), "label": f.label.as_str(),
            "decision": f.decision.as_str(), "reason": f.reason.as_str(), "control": e.control.as_str(),
            "total": e.total, "passed": e.passed, "flagged": e.flagged,
            "subject_hash": f.subject_hash, "leaf_hash": hex::encode(leaf_hash(&rec)), "key_id": f.key_id,
            "checkpoint_size": cp.size, "checkpoint_root": hex::encode(cp.root),
        }));
    }
    // the optional ledger copy: ONLY the marker, the records and the checkpoints (a fixed list of three names; nothing else in the directory is read)
    let tar = if cfg.include_ledger {
        let read = |rel: &str| {
            std::fs::read(ledger_dir.join(rel)).map_err(|_| io("cannot read a ledger file"))
        };
        let (m, r, c) = (
            read("MOCK-DATA.txt")?,
            read("evidence-ledger/records.log")?,
            read("evidence-ledger/checkpoints.log")?,
        );
        Some(ustar(&[
            ("MOCK-DATA.txt", &m),
            ("evidence-ledger/checkpoints.log", &c),
            ("evidence-ledger/records.log", &r),
        ])?)
    } else {
        None
    };
    let pages = n.div_ceil(size);
    let head = cps.last().ok_or_else(|| io("no checkpoint"))?;
    let mut meta = json!({
        "label": LABEL, "what_is_mock": WHAT_IS_MOCK, "what_is_real": WHAT_IS_REAL, "notes": notes,
        "records": n, "page_size": size, "pages": pages, "key_id": key_id(pubkey_hex), "pubkey": pubkey_hex,
        "verify_command": VERIFY_COMMAND, "not_claimed": NOT_CLAIMED,
        "checkpoint_head": {"size": head.size, "root": hex::encode(head.root)},
    });
    if let Some(t) = &tar {
        meta["ledger_tar"] = json!({"file": TAR_NAME, "bytes": t.len(), "blake3": blake3::hash(t).to_hex().to_string(), "how_to": TAR_HOW_TO});
    }
    let mut out: Vec<(String, Vec<u8>)> = vec![
        ("index.html".into(), INDEX_HTML.as_bytes().to_vec()),
        ("style.css".into(), STYLE_CSS.as_bytes().to_vec()),
        ("app.js".into(), APP_JS.as_bytes().to_vec()),
        ("data/meta.json".into(), json_text(&meta)?.into_bytes()),
    ];
    if let Some(t) = tar {
        out.push((TAR_NAME.into(), t));
    }
    for (k, chunk) in rows.chunks(size).enumerate() {
        let page = json!({"label": LABEL, "page": k + 1, "pages": pages, "records": chunk});
        out.push((
            format!("data/page-{:04}.json", k + 1),
            json_text(&page)?.into_bytes(),
        ));
    }
    std::fs::create_dir_all(out_dir.join("data"))
        .map_err(|_| io("cannot create the output directory"))?;
    let mut bytes = 0u64;
    for (name, b) in &out {
        std::fs::write(out_dir.join(name), b).map_err(|_| io("cannot write a file"))?;
        bytes += b.len() as u64;
    }
    Ok(Report {
        records: n,
        pages,
        bytes,
        key_id: key_id(pubkey_hex),
    })
}

#[cfg(test)]
mod tests {
    use super::ustar;

    #[test]
    fn u1_names_up_to_100_bytes_are_accepted_and_101_refused() {
        assert!(ustar(&[(&"a".repeat(100), b"x")]).is_ok());
        assert!(ustar(&[(&"a".repeat(101), b"x")]).is_err());
    }

    #[test]
    fn u2_every_data_size_pads_to_a_whole_block_and_the_system_tar_reads_it_back() {
        for n in [0usize, 1, 511, 512, 513, 1024, 1500] {
            let data = vec![b'z'; n];
            let t = ustar(&[("one.bin", &data), ("two.bin", b"second")]).unwrap();
            assert_eq!(t.len() % 512, 0, "size {n}");
            // header + data blocks for both entries + the 1024-byte end marker
            assert_eq!(
                t.len(),
                512 + n.div_ceil(512) * 512 + 512 + 512 + 1024,
                "size {n}"
            );
            let dir = std::env::temp_dir().join(format!("ustar-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let f = dir.join("a.tar");
            std::fs::write(&f, &t).unwrap();
            let o = std::process::Command::new("tar")
                .arg("-xf")
                .arg(&f)
                .arg("-C")
                .arg(&dir)
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "size {n}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            assert_eq!(
                std::fs::read(dir.join("one.bin")).unwrap(),
                data,
                "size {n}"
            );
            assert_eq!(std::fs::read(dir.join("two.bin")).unwrap(), b"second");
        }
    }
}
