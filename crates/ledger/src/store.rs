//! The append-only ledger store: a shared core with a file-backed and an in-memory front.

use crate::LedgerError;
use entropa_core::merkle::{leaf_hash, node_hash, Hash};
use entropa_core::transparency_log::Checkpoint;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_WITNESS_BYTES: usize = 64 * 1024;

/// An append-only ledger store: records, checkpoints and witness statements. There is no way to
/// change or remove what was written.
pub trait LedgerStore {
    /// Append a record (the bytes of a log record); returns its index.
    fn append(&mut self, record: &[u8]) -> Result<usize, LedgerError>;
    /// Number of records.
    fn len(&self) -> usize;
    /// True when there are no records.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The record at `index`.
    fn record(&self, index: usize) -> Option<Vec<u8>>;
    /// Store a signed checkpoint. It must cover no more records than exist, match the Merkle root
    /// of exactly that prefix, and not be smaller than the previous checkpoint.
    fn put_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), LedgerError>;
    /// All checkpoints, oldest first.
    fn checkpoints(&self) -> Vec<Checkpoint>;
    /// Store a witness statement (JSON text).
    fn put_witness(&mut self, statement_json: &str) -> Result<(), LedgerError>;
    /// All witness statements, oldest first.
    fn witnesses(&self) -> Vec<String>;
}

#[derive(Debug, Default)]
struct Core {
    records: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
    /// `levels[k - 1][i]` is the root of the aligned perfect subtree `leaves[i * 2^k .. (i + 1) * 2^k)`, built as leaves arrive (LEDGER-STORE-VERIFY).
    levels: Vec<Vec<Hash>>,
    checkpoints: Vec<Checkpoint>,
    witnesses: Vec<String>,
}

impl Core {
    fn check_record(rec: &[u8]) -> Result<(), LedgerError> {
        if rec.is_empty() {
            return Err(LedgerError::Invalid("record is empty".into()));
        }
        if rec.len() > MAX_RECORD_BYTES {
            return Err(LedgerError::Limit("record is larger than 64 KiB".into()));
        }
        Ok(())
    }

    /// The Merkle root of the first `m` leaves (the RFC 6962 shape of `entropa_core::merkle::root`), folded from at most log2(m) aligned subtrees: O(log m).
    fn prefix_root(&self, m: usize) -> Option<Hash> {
        if m == 0 || m > self.leaves.len() {
            return None;
        }
        Some(self.range_root(0, m))
    }

    /// The root of `leaves[offset .. offset + len)`; `offset` is a multiple of the largest power of two below `len` (or `len` is a power of two), so every left part is an aligned subtree.
    fn range_root(&self, offset: usize, len: usize) -> Hash {
        if len == 1 {
            return self.leaves[offset];
        }
        if len.is_power_of_two() {
            let k = len.trailing_zeros() as usize;
            return self.levels[k - 1][offset >> k];
        }
        let left = len.next_power_of_two() / 2;
        node_hash(
            &self.range_root(offset, left),
            &self.range_root(offset + left, len - left),
        )
    }

    fn push(&mut self, rec: &[u8]) -> usize {
        self.leaves.push(leaf_hash(rec));
        // complete every aligned subtree that this leaf closes
        let n = self.leaves.len();
        let mut k = 1;
        while n.is_multiple_of(1usize << k) {
            let i = n / (1usize << k) - 1;
            let (l, r) = if k == 1 {
                (self.leaves[2 * i], self.leaves[2 * i + 1])
            } else {
                (self.levels[k - 2][2 * i], self.levels[k - 2][2 * i + 1])
            };
            if self.levels.len() < k {
                self.levels.push(Vec::new());
            }
            self.levels[k - 1].push(node_hash(&l, &r));
            k += 1;
        }
        self.records.push(rec.to_vec());
        self.records.len() - 1
    }

    fn check_checkpoint(&self, cp: &Checkpoint) -> Result<(), LedgerError> {
        if cp.size > self.records.len() {
            return Err(LedgerError::Invalid(
                "checkpoint covers more records than exist".into(),
            ));
        }
        let expected = if cp.size == 0 {
            Some(leaf_hash(&[]))
        } else {
            self.prefix_root(cp.size)
        };
        if expected != Some(cp.root) {
            return Err(LedgerError::Invalid(
                "checkpoint root does not match the records".into(),
            ));
        }
        if let Some(last) = self.checkpoints.last() {
            if cp.size < last.size || (cp.size == last.size && cp.root != last.root) {
                return Err(LedgerError::Invalid(
                    "checkpoint is older than the previous one".into(),
                ));
            }
        }
        Ok(())
    }

    fn check_witness(s: &str) -> Result<(), LedgerError> {
        if s.len() > MAX_WITNESS_BYTES
            || s.contains('\n')
            || serde_json::from_str::<serde_json::Value>(s).is_err()
        {
            return Err(LedgerError::Invalid(
                "witness statement must be one line of JSON".into(),
            ));
        }
        Ok(())
    }
}

/// An in-memory store (tests and dry runs).
#[derive(Debug, Default)]
pub struct MemoryStore {
    core: Core,
}

impl LedgerStore for MemoryStore {
    fn append(&mut self, record: &[u8]) -> Result<usize, LedgerError> {
        Core::check_record(record)?;
        Ok(self.core.push(record))
    }
    fn len(&self) -> usize {
        self.core.records.len()
    }
    fn record(&self, index: usize) -> Option<Vec<u8>> {
        self.core.records.get(index).cloned()
    }
    fn put_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), LedgerError> {
        self.core.check_checkpoint(cp)?;
        self.core.checkpoints.push(cp.clone());
        Ok(())
    }
    fn checkpoints(&self) -> Vec<Checkpoint> {
        self.core.checkpoints.clone()
    }
    fn put_witness(&mut self, s: &str) -> Result<(), LedgerError> {
        Core::check_witness(s)?;
        self.core.witnesses.push(s.to_string());
        Ok(())
    }
    fn witnesses(&self) -> Vec<String> {
        self.core.witnesses.clone()
    }
}

/// A store kept in a local directory (`records.log`, `checkpoints.log`, `witnesses.log`, one hex or
/// JSON line per entry) with a lock file so only one writer has it open. A stale lock file left by a
/// crash must be removed by a person.
#[derive(Debug)]
pub struct FileStore {
    dir: PathBuf,
    lock: PathBuf,
    core: Core,
    read_only: bool,
}

impl Drop for FileStore {
    /// Releases the writer lock.
    fn drop(&mut self) {
        if !self.read_only {
            let _ = fs::remove_file(&self.lock);
        }
    }
}

fn io(e: std::io::Error) -> LedgerError {
    LedgerError::Io(format!("{:?}", e.kind()))
}

fn corrupt(what: &str) -> LedgerError {
    LedgerError::Corrupt(what.to_string())
}

fn lines(path: &Path) -> Result<Vec<String>, LedgerError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(e)),
    };
    if !text.is_empty() && !text.ends_with('\n') {
        return Err(corrupt("file ends with a partial line"));
    }
    Ok(text.lines().map(str::to_string).collect())
}

impl FileStore {
    /// Open or create the store in `dir`. Fails if another writer holds the lock, if a file ends in
    /// a partial line, or if the records no longer match the stored checkpoints.
    pub fn open(dir: &Path) -> Result<FileStore, LedgerError> {
        fs::create_dir_all(dir).map_err(io)?;
        let lock = dir.join(".lock");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
            .map_err(|_| {
                LedgerError::Io("the store is open elsewhere or a lock file is left behind".into())
            })?;
        let mut store = FileStore {
            dir: dir.to_path_buf(),
            lock,
            core: Core::default(),
            read_only: false,
        };
        store.load()?;
        Ok(store)
    }

    /// Open an EXISTING store for reading only: no directory is created, no lock file is written or removed, and every write is refused. It works on read-only
    /// media and while a writer holds the store (a reader sees the files as they were when it loaded; a half-written last line is refused like in `open`).
    pub fn open_read_only(dir: &Path) -> Result<FileStore, LedgerError> {
        if !dir.is_dir() {
            return Err(LedgerError::Io("the store directory does not exist".into()));
        }
        let mut store = FileStore {
            dir: dir.to_path_buf(),
            lock: dir.join(".lock"), // never created or removed by a read-only store (the drop guard and test ro3 pin that)
            core: Core::default(),
            read_only: true,
        };
        store.load()?;
        Ok(store)
    }

    fn load(&mut self) -> Result<(), LedgerError> {
        for line in lines(&self.dir.join("records.log"))? {
            let bytes = hex::decode(&line).map_err(|_| corrupt("a record line is not hex"))?;
            Core::check_record(&bytes)
                .map_err(|_| corrupt("a stored record is empty or too large"))?;
            self.core.push(&bytes);
        }
        for line in lines(&self.dir.join("checkpoints.log"))? {
            let cp: Checkpoint = serde_json::from_str(&line)
                .map_err(|_| corrupt("a checkpoint line is not valid"))?;
            self.core
                .check_checkpoint(&cp)
                .map_err(|_| corrupt("a checkpoint does not match the records"))?;
            self.core.checkpoints.push(cp);
        }
        for line in lines(&self.dir.join("witnesses.log"))? {
            Core::check_witness(&line).map_err(|_| corrupt("a witness line is not valid"))?;
            self.core.witnesses.push(line);
        }
        Ok(())
    }

    fn write_line(&self, file: &str, line: &str) -> Result<(), LedgerError> {
        if self.read_only {
            return Err(LedgerError::Io("the store is open read-only".into()));
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(file))
            .map_err(io)?;
        f.write_all(format!("{line}\n").as_bytes()).map_err(io)?;
        f.sync_data().map_err(io)
    }
}

impl LedgerStore for FileStore {
    fn append(&mut self, record: &[u8]) -> Result<usize, LedgerError> {
        Core::check_record(record)?;
        self.write_line("records.log", &hex::encode(record))?;
        Ok(self.core.push(record))
    }
    fn len(&self) -> usize {
        self.core.records.len()
    }
    fn record(&self, index: usize) -> Option<Vec<u8>> {
        self.core.records.get(index).cloned()
    }
    fn put_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), LedgerError> {
        self.core.check_checkpoint(cp)?;
        self.write_line(
            "checkpoints.log",
            &serde_json::to_string(cp).map_err(|_| LedgerError::Invalid("checkpoint".into()))?,
        )?;
        self.core.checkpoints.push(cp.clone());
        Ok(())
    }
    fn checkpoints(&self) -> Vec<Checkpoint> {
        self.core.checkpoints.clone()
    }
    fn put_witness(&mut self, s: &str) -> Result<(), LedgerError> {
        Core::check_witness(s)?;
        self.write_line("witnesses.log", s)?;
        self.core.witnesses.push(s.to_string());
        Ok(())
    }
    fn witnesses(&self) -> Vec<String> {
        self.core.witnesses.clone()
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
    use entropa_core::merkle::root as merkle_root;

    fn core(n: usize) -> Core {
        let mut c = Core::default();
        for i in 0..n {
            c.push(format!("rec-{i}").as_bytes());
        }
        c
    }

    #[test]
    fn d1_prefix_root_equals_the_from_scratch_root_for_every_size_up_to_300() {
        let c = core(300);
        for m in 1..=300 {
            assert_eq!(c.prefix_root(m), merkle_root(&c.leaves[..m]), "size {m}");
        }
    }

    #[test]
    fn d3_prefix_root_refuses_sizes_outside_one_to_len() {
        let c = core(10);
        assert_eq!(c.prefix_root(0), None);
        assert_eq!(c.prefix_root(11), None);
        assert!(c.prefix_root(10).is_some());
    }

    #[test]
    fn d2_prefix_root_equals_the_from_scratch_root_for_random_sizes_up_to_20000() {
        let c = core(20_000);
        let mut x = 20_261_215u64;
        for _ in 0..2_000 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let m = 1 + ((x >> 33) as usize) % 20_000;
            assert_eq!(c.prefix_root(m), merkle_root(&c.leaves[..m]), "size {m}");
        }
        // the sizes around the powers of two
        for k in 1..15u32 {
            for m in [(1usize << k) - 1, 1 << k, (1 << k) + 1] {
                assert_eq!(c.prefix_root(m), merkle_root(&c.leaves[..m]), "size {m}");
            }
        }
    }
}
