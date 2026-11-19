//! INS2 slice 2b: read the ledger files RAW (records.log, checkpoints.log), without the store's own refusals, so a verifier can say WHICH way a ledger is wrong.
use crate::LedgerError;
use entropa_core::anchor::{AnyCheckpoint, CheckpointV2};
use entropa_core::merkle::{leaf_hash, Hash};
use entropa_core::transparency_log::Checkpoint;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// The longest record line read (hex of a 64 KiB record, and the newline).
pub const MAX_RECORD_LINE: usize = 2 * 64 * 1024 + 2;
/// The longest checkpoint line read (a v2 checkpoint is about 11 KB).
pub const MAX_CHECKPOINT_LINE: usize = 32 * 1024;
const MAX_RECORD_BYTES: usize = 64 * 1024;

/// What the verifier needs from a ledger directory: one leaf hash per record and the checkpoints in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLedger {
    /// Leaf hash of each record, in order.
    pub leaves: Vec<Hash>,
    /// Every checkpoint line, v1 or v2.
    pub checkpoints: Vec<AnyCheckpoint>,
}

fn corrupt(what: &str) -> LedgerError {
    LedgerError::Corrupt(what.to_string())
}

/// Every line of a file, each read with a hard length limit; a missing file has no lines; a last line without its newline is refused.
fn bounded_lines(
    path: &Path,
    max: usize,
    mut each: impl FnMut(&[u8]) -> Result<(), LedgerError>,
) -> Result<(), LedgerError> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(LedgerError::Io("a ledger file cannot be read".into())),
    };
    let mut r = BufReader::new(f);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = r
            .by_ref()
            .take(max as u64 + 1)
            .read_until(b'\n', &mut buf)
            .map_err(|_| LedgerError::Io("a ledger file cannot be read".into()))?;
        if n == 0 {
            return Ok(());
        }
        if buf.last() != Some(&b'\n') {
            return Err(corrupt(if buf.len() > max {
                "a line is too long"
            } else {
                "file ends with a partial line"
            }));
        }
        buf.pop();
        if buf.len() > max {
            return Err(corrupt("a line is too long"));
        }
        each(&buf)?;
    }
}

/// True when any hex field of a checkpoint line holds an upper-case digit (the documented layout is lower case).
pub(crate) fn upper_case_hex_field(v: &serde_json::Value) -> bool {
    ["root", "prev", "signature", "proposer_pubkey"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(serde_json::Value::as_str))
        .any(|t| t.bytes().any(|b| b.is_ascii_uppercase()))
}

const V1_KEYS: [&str; 5] = ["root", "size", "timestamp", "proposer_pubkey", "signature"];
const V2_KEYS: [&str; 7] = [
    "root",
    "size",
    "timestamp",
    "proposer_pubkey",
    "signature",
    "counter",
    "prev",
];
/// Largest whole number that survives a round trip through JSON numbers everywhere (the bound the anchor decoder uses).
const MAX_SAFE_INT: u64 = (1 << 53) - 1;

/// One checkpoint line: strict JSON (a repeated key is refused), a CLOSED key set per version (a line with a `counter` is v2; v1: root, size, timestamp, proposer_pubkey, signature; v2 adds counter and prev),
/// whole numbers not above 2^53 - 1, lower-case hex. Any other line is `Corrupt` with a fixed text that never echoes it.
pub(crate) fn parse_checkpoint_text(text: &str) -> Result<AnyCheckpoint, LedgerError> {
    let v = entropa_witness::strict_json::from_str(text)
        .map_err(|_| corrupt("a checkpoint line is not valid"))?;
    let Some(obj) = v.as_object() else {
        return Err(corrupt("a checkpoint line is not valid"));
    };
    let v2 = obj.contains_key("counter");
    let want: &[&str] = if v2 { &V2_KEYS } else { &V1_KEYS };
    if obj.len() != want.len() || !want.iter().all(|k| obj.contains_key(*k)) {
        return Err(corrupt(
            "a checkpoint line has unexpected or missing fields",
        ));
    }
    for k in ["size", "timestamp", "counter"] {
        if let Some(n) = obj.get(k) {
            if !n.as_u64().is_some_and(|x| x <= MAX_SAFE_INT) {
                return Err(corrupt(
                    "a checkpoint number is not a whole number in range",
                ));
            }
        }
    }
    if upper_case_hex_field(&v) {
        return Err(corrupt("a checkpoint hex field is not lower-case"));
    }
    if v2 {
        serde_json::from_value::<CheckpointV2>(v)
            .map(AnyCheckpoint::V2)
            .map_err(|_| corrupt("a checkpoint line is not valid"))
    } else {
        serde_json::from_value::<Checkpoint>(v)
            .map(AnyCheckpoint::V1)
            .map_err(|_| corrupt("a checkpoint line is not valid"))
    }
}

fn parse_checkpoint(line: &[u8]) -> Result<AnyCheckpoint, LedgerError> {
    let text = std::str::from_utf8(line).map_err(|_| corrupt("a checkpoint line is not text"))?;
    parse_checkpoint_text(text)
}

/// Read `dir/records.log` and `dir/checkpoints.log`. A missing file is empty. Any malformed content is `LedgerError::Corrupt` with a fixed text.
pub fn read_raw(dir: &Path) -> Result<RawLedger, LedgerError> {
    read_raw_with(dir, &mut |_| {})
}

/// Like [`read_raw`], and hands every record's bytes to `on_record` as it is read (so a caller can check each record without keeping them all).
pub fn read_raw_with(
    dir: &Path,
    on_record: &mut dyn FnMut(&[u8]),
) -> Result<RawLedger, LedgerError> {
    let mut leaves = Vec::new();
    bounded_lines(&dir.join("records.log"), MAX_RECORD_LINE, |l| {
        let text = std::str::from_utf8(l).map_err(|_| corrupt("a record line is not hex"))?;
        if text.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(corrupt("a record line is not lower-case hex"));
        }
        let bytes = hex::decode(text).map_err(|_| corrupt("a record line is not hex"))?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(corrupt("a stored record is empty or too large"));
        }
        leaves.push(leaf_hash(&bytes));
        on_record(&bytes);
        Ok(())
    })?;
    let mut checkpoints = Vec::new();
    bounded_lines(&dir.join("checkpoints.log"), MAX_CHECKPOINT_LINE, |l| {
        checkpoints.push(parse_checkpoint(l)?);
        Ok(())
    })?;
    Ok(RawLedger {
        leaves,
        checkpoints,
    })
}
