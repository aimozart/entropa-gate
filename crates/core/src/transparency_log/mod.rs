//! The end-to-end transparency-log prototype — see
//! `a stage record (not published)`. Wires `merkle.rs`'s pure primitives into a
//! usable append + checkpoint + receipt + independent-verification flow. Still pure, no
//! I/O: `TransparencyLog` is an in-memory structure, same posture as `Chain` — a real
//! deployment would persist `records` behind an `AppendOnlyStore` (below) rather than
//! holding everything in RAM forever.

mod batch_receipt;
mod checkpoint;
mod receipt;
mod record;
mod store;

pub use checkpoint::Checkpoint;
pub use receipt::{verify_receipt, Receipt};
pub use record::{
    decode_record, decode_record_or_marker, encode_record, RecordError, MAX_FIELD_BYTES,
    RECORD_FORMAT_VERSION,
};
pub use store::{AppendOnlyStore, InMemoryStore};

use crate::merkle::{self, Hash};
use crate::pqc::Probe;
use checkpoint::checkpoint_digest;

/// An in-memory, append-only Merkle log. A real deployment persists `records` behind an
/// [`AppendOnlyStore`] rather than holding everything in RAM — this struct is the pure
/// logic layer, same posture as the retired in-memory `Chain`.
///
/// `frontier[i]` caches the root of a complete subtree of size `2^i`, if one currently
/// exists unpaired at that level — a binary-counter-style incremental structure (RFC
/// 6962 calls this the tree's "frontier"). This is what makes `root()`/`checkpoint()`
/// amortized O(1) per append (worst case O(log n), bounded by tree height, never by
/// total log size) instead of rehashing all history on every call. Real production
/// incident this fixes, 2026-08-25: at the live chain's actual scale (~193,000+
/// records), the naive full-rebuild approach cost 36ms *per checkpoint call* and grew
/// without bound — exactly the class of problem event-driven checkpointing (running on
/// every `/api/tx`) cannot tolerate.
#[derive(Debug, Default, Clone)]
pub struct TransparencyLog {
    records: Vec<Vec<u8>>,
    frontier: Vec<Option<Hash>>,
    /// Cached per-record leaf hashes, appended to incrementally alongside `records`.
    /// `receipt()` used to call `leaves()`, which rebuilt this entire array from
    /// scratch on every call -- O(n) per receipt, and O(n^2) for `full_export`'s loop
    /// over every index. Real production incident, 2026-08-27: this produced 17-second,
    /// then-failing 500s on the dashboard's full-history export at Pinnacle Financial's
    /// live record count. See `a_single_receipt_call_stays_fast_regardless_of_existing_log_size`.
    leaf_hashes: Vec<Hash>,
}

impl TransparencyLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a record, returning its index in the log. Updates the frontier
    /// incrementally: amortized O(1), worst case O(log n) when a long run of
    /// same-size peaks cascades into a merge (the same shape as a binary counter's
    /// carry chain).
    pub fn append(&mut self, record: &[u8]) -> usize {
        let index = self.records.len();
        self.records.push(record.to_vec());
        let leaf = merkle::leaf_hash(&self.records[index]);
        self.leaf_hashes.push(leaf);
        let mut carry = leaf;
        let mut level = 0;
        loop {
            match self.frontier.get(level).copied().flatten() {
                Some(existing) => {
                    carry = merkle::node_hash(&existing, &carry);
                    self.frontier[level] = None;
                    level += 1;
                }
                None => {
                    if level == self.frontier.len() {
                        self.frontier.push(Some(carry));
                    } else {
                        self.frontier[level] = Some(carry);
                    }
                    break;
                }
            }
        }
        index
    }

    /// Number of records appended so far.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// The record bytes at `index`, if any (read-only access for consumers that replay a log).
    pub fn record(&self, index: usize) -> Option<&[u8]> {
        self.records.get(index).map(Vec::as_slice)
    }

    /// True when no record has been appended.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn leaves(&self) -> &[Hash] {
        &self.leaf_hashes
    }

    /// The Merkle root over every appended record so far — O(log n), combining the
    /// cached frontier peaks rather than rehashing history. Peaks are folded from
    /// smallest (lowest level, most recently completed) to largest, each larger peak
    /// becoming the left argument over the accumulated smaller ones on the right —
    /// this exactly mirrors `merkle::root`'s own left-biased recursive split, so it's
    /// provably the same root a full rebuild would produce (see the
    /// `incremental_root_matches_a_full_rebuild_for_every_size` regression test).
    pub fn root(&self) -> Option<Hash> {
        let mut acc: Option<Hash> = None;
        for peak in self.frontier.iter().flatten() {
            acc = Some(match acc {
                None => *peak,
                Some(smaller) => merkle::node_hash(peak, &smaller),
            });
        }
        acc
    }

    /// Sign the current root + size — this is the checkpoint a customer's receipt is
    /// verified against, and what would be published/externally anchored periodically.
    pub fn checkpoint(&self, signer: &Probe, timestamp: u64) -> Checkpoint {
        let (root, size, digest) = self.checkpoint_parts(timestamp);
        self.assemble_checkpoint(
            root,
            size,
            timestamp,
            signer.pubkey_hex(),
            signer.sign_hex(&digest),
        )
    }

    fn checkpoint_parts(&self, timestamp: u64) -> (Hash, usize, Vec<u8>) {
        let root = self.root().unwrap_or_else(|| merkle::leaf_hash(b""));
        let size = self.len();
        (root, size, checkpoint_digest(&root, size, timestamp))
    }

    fn assemble_checkpoint(
        &self,
        root: Hash,
        size: usize,
        timestamp: u64,
        proposer_pubkey: String,
        signature: String,
    ) -> Checkpoint {
        Checkpoint {
            root,
            size,
            timestamp,
            proposer_pubkey,
            signature,
        }
    }

    /// Like [`Self::checkpoint`] but signs through any [`crate::signer::CheckpointSigner`] backend
    /// (in-process key or managed KMS). Returns the backend's error and changes nothing
    /// if signing fails.
    pub fn checkpoint_with<S: crate::signer::CheckpointSigner>(
        &self,
        signer: &S,
        timestamp: u64,
    ) -> Result<Checkpoint, crate::signer::SignError> {
        let (root, size, digest) = self.checkpoint_parts(timestamp);
        let signature = signer.try_sign_hex(&digest)?;
        if !crate::pqc::verify_hex(&signer.pubkey_hex(), &digest, &signature) {
            return Err(crate::signer::SignError::Backend(
                "signature does not verify under the signer's public key".into(),
            ));
        }
        Ok(Checkpoint {
            root,
            size,
            timestamp,
            proposer_pubkey: signer.pubkey_hex(),
            signature,
        })
    }

    /// Build a receipt for `index`, proving it's included under `checkpoint`. `None` if
    /// `index` is out of range, or the checkpoint's size doesn't match this log's
    /// current size (the proof would be for the wrong tree shape).
    pub fn receipt(&self, index: usize, checkpoint: &Checkpoint) -> Option<Receipt> {
        self.receipts_for(std::slice::from_ref(&index), checkpoint)
            .into_iter()
            .next()
            .flatten()
    }

    /// Build receipts for many indices against the *same* checkpoint in one pass.
    /// Real production incident, 2026-08-27: both `full_export` and `get_chain` used
    /// to loop plain `receipt()` once per index, which was O(n) per call -- making
    /// the whole loop O(n^2). See `batch_receipt`'s module doc for the full incident
    /// writeup and the memoization fix this delegates to.
    pub fn receipts_for(&self, indices: &[usize], checkpoint: &Checkpoint) -> Vec<Option<Receipt>> {
        if checkpoint.size > self.records.len() || checkpoint.size == 0 {
            return indices.iter().map(|_| None).collect();
        }
        // Prove against the exact prefix the checkpoint committed to, not whatever
        // the log has grown to since -- append-only history means that prefix's
        // hashes never change, so a proof against it stays valid indefinitely, even
        // while concurrent writers keep extending the log past it.
        let leaves = &self.leaves()[..checkpoint.size];
        batch_receipt::proofs_for(leaves, indices)
            .into_iter()
            .zip(indices)
            .map(|(proof, &index)| {
                let proof = proof?;
                Some(Receipt {
                    index,
                    record: self.records[index].clone(),
                    proof,
                    checkpoint: checkpoint.clone(),
                })
            })
            .collect()
    }
}

#[cfg(all(test, feature = "signing"))]
pub(crate) fn checkpoint_digest_for_tests(root: &Hash, size: usize, ts: u64) -> Vec<u8> {
    checkpoint_digest(root, size, ts)
}

#[cfg(all(test, feature = "signing"))]
mod tests {
    #[test]
    fn record_returns_the_appended_bytes_and_none_out_of_range() {
        let mut log = TransparencyLog::new();
        log.append(b"first");
        log.append(b"");
        assert_eq!(log.record(0), Some(&b"first"[..]));
        assert_eq!(log.record(1), Some(&b""[..]));
        assert_eq!(log.record(2), None);
    }

    #[test]
    fn receipts_are_refused_for_a_zero_size_or_oversized_checkpoint() {
        let p = Probe::spawn();
        let mut log = TransparencyLog::new();
        let empty_cp = log.checkpoint(&p, 1);
        log.append(b"a");
        assert_eq!(empty_cp.size, 0);
        assert!(log.receipt(0, &empty_cp).is_none(), "size-0 checkpoint");
        let mut oversized = log.checkpoint(&p, 2);
        oversized.size = 5;
        assert!(
            log.receipt(0, &oversized).is_none(),
            "checkpoint beyond the log"
        );
        let good = log.checkpoint(&p, 3);
        assert!(log.receipt(0, &good).is_some());
    }

    #[test]
    fn len_and_is_empty_track_appends() {
        let mut log = TransparencyLog::new();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        log.append(b"a");
        log.append(b"b");
        assert_eq!(log.len(), 2);
        assert!(!log.is_empty());
    }

    use super::*;

    fn probe() -> Probe {
        Probe::spawn()
    }

    /// Real-scale benchmark, per the sequencing decision to benchmark before deciding
    /// to go live: checkpointing on every append (the event-driven design this whole
    /// migration requires — see a stage record (not published)'s "Checkpointing
    /// must be event-driven" section) at the live chain's actual current scale
    /// (~193,000+ records and growing). `#[ignore]`d — real hashing work, too slow for
    /// every `cargo test --workspace` run, same posture as `chain.rs`'s own real-scale
    /// forecast test. Run explicitly with `cargo test -- --ignored --nocapture` before
    /// trusting this design's per-request cost at production scale.
    #[test]
    #[ignore]
    fn checkpoint_cost_at_real_production_scale() {
        let mut log = TransparencyLog::new();
        let p = probe();
        for size in [1_000usize, 10_000, 50_000, 100_000, 200_000] {
            while log.len() < size {
                let i = log.len();
                log.append(format!("record-{i}").as_bytes());
            }
            let start = std::time::Instant::now();
            let _checkpoint = log.checkpoint(&p, 1_000);
            let elapsed = start.elapsed();
            println!("log_size={size:>7}  single_checkpoint_cost={elapsed:?}");
        }
    }

    /// The actual regression this fix exists to close: the cost of *one more* append/
    /// checkpoint call, given a log that already has real production-scale history,
    /// must stay bounded by tree height (O(log n)), not grow with total log size
    /// (O(n)). Confirmed red against the current full-rebuild implementation before
    /// the fix (36ms+ at 200,000 records, only getting worse); green after switching
    /// to an incremental frontier. 2ms is a generous bound -- real cost should land
    /// well under 1ms even at this size once fixed.
    #[test]
    #[ignore]
    fn a_single_additional_checkpoint_stays_fast_regardless_of_existing_log_size() {
        let mut log = TransparencyLog::new();
        let p = probe();
        for i in 0..200_000usize {
            log.append(format!("record-{i}").as_bytes());
        }
        let start = std::time::Instant::now();
        let _checkpoint = log.checkpoint(&p, 1_000);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 2,
            "a single additional checkpoint on a 200,000-record log took {elapsed:?} -- \
             should be bounded by tree height (~18 levels), not total log size"
        );
    }

    #[test]
    fn appending_a_record_returns_its_index_and_advances_size() {
        let mut log = TransparencyLog::new();
        assert_eq!(log.append(b"first"), 0);
        assert_eq!(log.append(b"second"), 1);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn checkpoint_root_matches_the_appended_records() {
        let mut log = TransparencyLog::new();
        log.append(b"a");
        log.append(b"b");
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        assert_eq!(checkpoint.size, 2);
        assert_eq!(checkpoint.root, log.root().unwrap());
    }

    /// The correctness proof the whole speed fix hinges on: the incremental frontier
    /// must produce *exactly* the same root a naive full rebuild would, for every
    /// size, including every power-of-two boundary (the exact points where a cascade
    /// merge happens) -- a fast wrong answer would be worse than a slow correct one.
    #[test]
    fn incremental_root_matches_a_full_rebuild_for_every_size() {
        let mut log = TransparencyLog::new();
        let mut leaves = Vec::new();
        for i in 0..130u32 {
            log.append(format!("record-{i}").as_bytes());
            leaves.push(merkle::leaf_hash(format!("record-{i}").as_bytes()));
            let full_rebuild = merkle::root(&leaves);
            assert_eq!(
                log.root(),
                full_rebuild,
                "size {} (binary {:b}) diverged from a full rebuild",
                leaves.len(),
                leaves.len()
            );
        }
    }

    #[test]
    fn receipt_for_a_real_record_verifies_independently() {
        let mut log = TransparencyLog::new();
        log.append(b"alpha");
        log.append(b"beta");
        log.append(b"gamma");
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        let receipt = log.receipt(1, &checkpoint).expect("index 1 exists");
        assert!(verify_receipt(&receipt, &p.pubkey_hex()));
    }

    #[test]
    fn receipt_out_of_range_index_is_none() {
        let mut log = TransparencyLog::new();
        log.append(b"only-one");
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        assert!(log.receipt(5, &checkpoint).is_none());
    }

    /// Direct correctness test for `receipts_for` itself (not just via `receipt()`
    /// delegating to it with one index, and not just the performance regression
    /// tests in `batch_receipt.rs`): a batch of receipts for a mix of valid and
    /// out-of-range indices against one checkpoint must each independently verify
    /// or be `None`, in the same order the indices were requested.
    #[test]
    fn receipts_for_returns_independently_verifiable_receipts_in_request_order() {
        let mut log = TransparencyLog::new();
        for i in 0..5u32 {
            log.append(format!("record-{i}").as_bytes());
        }
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        let receipts = log.receipts_for(&[3, 0, 99, 4], &checkpoint);
        assert_eq!(receipts.len(), 4);
        assert_eq!(receipts[0].as_ref().unwrap().index, 3);
        assert_eq!(receipts[1].as_ref().unwrap().index, 0);
        assert!(receipts[2].is_none(), "index 99 is out of range");
        assert_eq!(receipts[3].as_ref().unwrap().index, 4);
        for r in receipts.into_iter().flatten() {
            assert!(verify_receipt(&r, &p.pubkey_hex()));
        }
    }

    #[test]
    fn receipts_for_against_an_empty_log_returns_all_none() {
        let log = TransparencyLog::new();
        let p = probe();
        let checkpoint = log.checkpoint(&p, 1_000);
        let receipts = log.receipts_for(&[0, 1], &checkpoint);
        assert_eq!(receipts, vec![None, None]);
    }

    /// The real production bug: under concurrent writers, a checkpoint is always
    /// taken slightly behind the true log length (append happens, then persistence,
    /// then the checkpoint is recomputed). A reader hitting the log in that gap must
    /// still get a valid receipt for anything the checkpoint actually covers --
    /// stale-but-correct, not empty. This is the append-only Merkle property that
    /// makes transparency logs useful in the first place: a proof against an older,
    /// smaller checkpoint stays valid forever, because history is never rewritten.
    #[test]
    fn receipt_against_a_checkpoint_older_than_the_current_log_still_verifies() {
        let mut log = TransparencyLog::new();
        log.append(b"alpha");
        log.append(b"beta");
        let p = probe();
        let stale_checkpoint = log.checkpoint(&p, 1_000);
        // More records land after the checkpoint was taken -- the real-world race.
        log.append(b"gamma");
        log.append(b"delta");

        let receipt = log
            .receipt(1, &stale_checkpoint)
            .expect("a receipt against a still-valid, older checkpoint must not be None");
        assert!(verify_receipt(&receipt, &p.pubkey_hex()));
    }

    /// A checkpoint can never prove an index it didn't yet cover, even if the log
    /// has since grown past it -- that record wasn't part of the tree this
    /// checkpoint's signature actually committed to.
    #[test]
    fn receipt_cannot_prove_an_index_the_checkpoint_did_not_yet_cover() {
        let mut log = TransparencyLog::new();
        log.append(b"alpha");
        let p = probe();
        let stale_checkpoint = log.checkpoint(&p, 1_000);
        log.append(b"beta"); // index 1, added after the checkpoint

        assert!(log.receipt(1, &stale_checkpoint).is_none());
    }

    /// The end-to-end scenario this whole design exists to prove: once a checkpoint is
    /// published and handed to a customer as part of their receipt, nobody -- not even
    /// the operator -- can silently replace what came after it without the customer's
    /// own receipt failing to verify against the new, rewritten checkpoint.
    #[test]
    fn a_history_rewrite_after_checkpointing_is_detected_end_to_end() {
        let mut log = TransparencyLog::new();
        log.append(b"real-record-0");
        log.append(b"real-record-1");
        let p = probe();

        // Customer gets a receipt for record 0, checkpointed at size 2.
        let honest_checkpoint = log.checkpoint(&p, 1_000);
        let customer_receipt = log.receipt(0, &honest_checkpoint).unwrap();
        assert!(verify_receipt(&customer_receipt, &p.pubkey_hex()));

        // Operator attempts to quietly rewrite history: replace record 1 with something
        // else and re-issue a new checkpoint over the altered log.
        let mut rewritten_log = TransparencyLog::new();
        rewritten_log.append(b"real-record-0");
        rewritten_log.append(b"secretly-different-record-1");
        let rewritten_checkpoint = rewritten_log.checkpoint(&p, 1_000);

        // The customer's original receipt must NOT verify against the rewritten
        // checkpoint -- the record it actually holds proof for is record 0, whose
        // inclusion proof was computed against the honest tree's shape/siblings, not
        // the rewritten one. Reusing the same proof against a different root/checkpoint
        // must fail.
        let receipt_against_rewrite = Receipt {
            checkpoint: rewritten_checkpoint,
            ..customer_receipt.clone()
        };
        assert!(!verify_receipt(&receipt_against_rewrite, &p.pubkey_hex()));

        // And the customer's real, original receipt continues to verify against the
        // honest checkpoint they actually received -- the rewrite didn't retroactively
        // invalidate anything real, it just can't be smuggled in as a replacement.
        assert!(verify_receipt(&customer_receipt, &p.pubkey_hex()));
    }
}
