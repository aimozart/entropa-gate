//! Log sources. v1: a JSON export of the log, loaded once at startup.

use entropa_core::transparency_log::Checkpoint;
use serde::Deserialize;

/// Read-only access to a log, as seen by `log_head` and `list_records`.
pub trait LogSource: Send {
    /// `"file"` or `"http"`.
    fn kind(&self) -> &'static str;
    /// The newest checkpoint the source knows.
    fn head(&self) -> Result<Checkpoint, String>;
    /// Records with index >= `since`, at most `limit`, as `(index, record bytes)`.
    fn read(&self, since: usize, limit: usize) -> Result<Vec<(usize, Vec<u8>)>, String>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    checkpoint: Checkpoint,
    records: Vec<String>,
}

/// A log exported to JSON: `{"checkpoint": {...}, "records": ["<hex>", ...]}`.
#[derive(Debug)]
pub struct FileSource {
    head: Checkpoint,
    records: Vec<Vec<u8>>,
}

impl FileSource {
    /// Parse an exported log. The number of records must equal the checkpoint size.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let export: Export = serde_json::from_str(text)
            .map_err(|_| "export is not valid JSON of the expected shape".to_string())?;
        let records = export
            .records
            .iter()
            .map(|h| hex::decode(h).map_err(|_| "a record is not valid hex".to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        if records.len() != export.checkpoint.size {
            return Err("the number of records does not match the checkpoint size".into());
        }
        Ok(Self {
            head: export.checkpoint,
            records,
        })
    }
}

impl LogSource for FileSource {
    fn kind(&self) -> &'static str {
        "file"
    }
    fn head(&self) -> Result<Checkpoint, String> {
        Ok(self.head.clone())
    }
    fn read(&self, since: usize, limit: usize) -> Result<Vec<(usize, Vec<u8>)>, String> {
        Ok(self
            .records
            .iter()
            .enumerate()
            .skip(since)
            .take(limit)
            .map(|(i, r)| (i, r.clone()))
            .collect())
    }
}
