//! The persistence boundary a real deployment backs `TransparencyLog`'s records with.

/// An append-only persistence boundary — deliberately exposes no update/delete method
/// at all, so a rewrite is structurally impossible at the application layer regardless
/// of what any calling code intends. A real deployment backs this with GCS Object
/// Retention Lock (WORM) so the *storage layer itself* also refuses modification, not
/// just this trait's shape — that enforcement is a bucket policy configured at deploy
/// time, not Rust code, and is out of scope for this prototype.
pub trait AppendOnlyStore {
    /// Backend-specific error type.
    type Error;

    /// Append a record, returning its index.
    fn append(&mut self, record: &[u8]) -> Result<usize, Self::Error>;
    /// Read the record at `index`, or `None` if out of range.
    fn read(&self, index: usize) -> Result<Option<Vec<u8>>, Self::Error>;
    /// Number of stored records.
    fn len(&self) -> usize;
    /// True when nothing is stored.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A trivial in-memory `AppendOnlyStore`, for tests/local dev — mirrors the role
/// `MockBrain` plays for `entropa-agents`: a real, working, offline stand-in, not a
/// placeholder.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    records: Vec<Vec<u8>>,
}

impl AppendOnlyStore for InMemoryStore {
    type Error = std::convert::Infallible;

    fn append(&mut self, record: &[u8]) -> Result<usize, Self::Error> {
        self.records.push(record.to_vec());
        Ok(self.records.len() - 1)
    }

    fn read(&self, index: usize) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.records.get(index).cloned())
    }

    fn len(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_store_is_empty_and_reads_nothing() {
        let s = InMemoryStore::default();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.read(0), Ok(None));
    }

    #[test]
    fn append_returns_sequential_indices_and_read_returns_the_exact_bytes() {
        let mut s = InMemoryStore::default();
        assert_eq!(s.append(b"first"), Ok(0));
        assert_eq!(s.append(b""), Ok(1));
        assert_eq!(s.append(&[9, 8, 7]), Ok(2));
        assert!(!s.is_empty());
        assert_eq!(s.len(), 3);
        assert_eq!(s.read(0), Ok(Some(b"first".to_vec())));
        assert_eq!(s.read(1), Ok(Some(Vec::new())));
        assert_eq!(s.read(2), Ok(Some(vec![9, 8, 7])));
        assert_eq!(s.read(3), Ok(None));
    }
}
