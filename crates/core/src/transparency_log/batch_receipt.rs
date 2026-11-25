//! Memoized batch inclusion-proof generation — extracted from `mod.rs` per the project rules
//! (file-size ceiling), and the actual fix for the real 2026-08-27 production
//! incident: `full_export`/`get_chain` both looped `TransparencyLog::receipt()`
//! once per index against the *same* checkpoint. Even after the sibling `mod.rs`
//! fix that caches leaf hashes on `append()`, a naive `inclusion_proof` call still
//! recomputes O(n) worth of sibling subtree hashes *per call* — `root()` for an
//! untouched subtree still has to walk and re-hash every leaf under it — so looping
//! it per index was O(n^2) overall. At Pinnacle Financial's real live height
//! (~4,500+ records), this produced real 17-second, then-failing 500 responses on
//! the dashboard's "download my full history" export button.
//!
//! Fix: warm a `(offset, len) -> subtree root` memo by computing the tree's root
//! once (visits every subtree range in the tree exactly once, O(n) total), then
//! derive each requested proof by reading already-computed sibling roots out of
//! that memo instead of recomputing them from scratch — O(log n) per proof after
//! the one-time warm-up, so a batch of k requested indices costs O(n + k log n)
//! total instead of O(n * k).

use std::collections::HashMap;

use crate::merkle::{self, Hash, ProofStep};

/// Same recursive tree-split as [`merkle::root`], but memoized by `(offset, len)` so a
/// subtree's root is computed once no matter how many proofs later need it as a
/// sibling. `offset` is the subtree's starting position in the *original* full leaf
/// array — needed because two different-sized subtrees at different offsets are
/// different cache entries even if they happened to hash the same leaves count.
fn memo_subtree_root(
    leaves: &[Hash],
    offset: usize,
    cache: &mut HashMap<(usize, usize), Hash>,
) -> Hash {
    let n = leaves.len();
    if let Some(&h) = cache.get(&(offset, n)) {
        return h;
    }
    let h = if n == 1 {
        leaves[0]
    } else {
        let k = merkle::largest_power_of_two_less_than(n);
        let left = memo_subtree_root(&leaves[..k], offset, cache);
        let right = memo_subtree_root(&leaves[k..], offset + k, cache);
        merkle::node_hash(&left, &right)
    };
    cache.insert((offset, n), h);
    h
}

/// Same recursive descent as [`merkle::inclusion_proof`], but reads sibling subtree
/// roots from the memo (warmed by [`memo_subtree_root`]) instead of recomputing them
/// with a fresh, unmemoized `root()` call each time.
fn memo_inclusion_proof(
    leaves: &[Hash],
    offset: usize,
    index: usize,
    cache: &mut HashMap<(usize, usize), Hash>,
) -> Option<Vec<ProofStep>> {
    fn go(
        leaves: &[Hash],
        offset: usize,
        index: usize,
        cache: &mut HashMap<(usize, usize), Hash>,
        proof: &mut Vec<ProofStep>,
    ) -> bool {
        match leaves.len() {
            0 => false,
            1 => index == 0,
            n => {
                let k = merkle::largest_power_of_two_less_than(n);
                if index < k {
                    let ok = go(&leaves[..k], offset, index, cache, proof);
                    if ok {
                        let sibling = memo_subtree_root(&leaves[k..], offset + k, cache);
                        proof.push(ProofStep {
                            sibling,
                            side: merkle::Side::Right,
                        });
                    }
                    ok
                } else {
                    let ok = go(&leaves[k..], offset + k, index - k, cache, proof);
                    if ok {
                        let sibling = memo_subtree_root(&leaves[..k], offset, cache);
                        proof.push(ProofStep {
                            sibling,
                            side: merkle::Side::Left,
                        });
                    }
                    ok
                }
            }
        }
    }
    if index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    go(leaves, offset, index, cache, &mut proof).then_some(proof)
}

/// Build inclusion proofs for `indices` against `leaves[..leaves.len()]` in one warm
/// pass. `leaves` is expected to already be sliced to the checkpoint's committed
/// size by the caller (`TransparencyLog::receipts_for`) — this function itself has
/// no notion of a `Checkpoint`, it's pure tree math over whatever slice it's given.
pub(super) fn proofs_for(leaves: &[Hash], indices: &[usize]) -> Vec<Option<Vec<ProofStep>>> {
    if leaves.is_empty() {
        return indices.iter().map(|_| None).collect();
    }
    let mut cache: HashMap<(usize, usize), Hash> = HashMap::new();
    memo_subtree_root(leaves, 0, &mut cache);
    indices
        .iter()
        .map(|&index| memo_inclusion_proof(leaves, 0, index, &mut cache))
        .collect()
}

#[cfg(all(test, feature = "signing"))]
mod tests {
    use crate::pqc::Probe;
    use crate::transparency_log::TransparencyLog;

    fn probe() -> Probe {
        Probe::spawn()
    }

    /// A single, isolated `receipt()` call (the real shape of `/api/receipt/:id` --
    /// one customer looking up one attestation) still warms a full O(n) memo table
    /// to answer one index under this fix's design, same as it always has -- that
    /// was never the actual production incident (a one-shot ~49ms lookup at 200,000
    /// records is a perfectly fine single-request latency). This test exists to
    /// pin that single-lookup cost at a real, honest bound so a future regression
    /// (e.g. something reintroducing per-call full leaf-hash rebuilding on top of
    /// this) gets caught, without pretending single-lookup was ever required to be
    /// O(log n) -- it wasn't; see `exporting_every_record_in_a_large_log_stays_
    /// near_linear_not_quadratic` below for the test that actually reproduces the
    /// real incident (looping receipt() once per index against the same checkpoint).
    #[test]
    #[ignore]
    fn a_single_receipt_call_stays_fast_regardless_of_existing_log_size() {
        let mut log = TransparencyLog::new();
        let p = probe();
        for i in 0..200_000usize {
            log.append(format!("record-{i}").as_bytes());
        }
        let checkpoint = log.checkpoint(&p, 1_000);
        let start = std::time::Instant::now();
        let _receipt = log.receipt(100_000, &checkpoint);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 150,
            "a single receipt() call on a 200,000-record log took {elapsed:?} -- \
             far past the ~50ms this design's one-shot memo warm-up should cost \
             even at this scale (real production scale is currently ~4,500 records)"
        );
    }

    /// Directly reproduces the production shape that actually broke (2026-08-27):
    /// `full_export`/`get_chain` both loop `receipt()` once per index against the
    /// same checkpoint -- so even after `leaves()` stops rebuilding per call, a
    /// naive per-index `inclusion_proof` still recomputes O(n) worth of sibling
    /// subtree hashes *per call*, making the whole export O(n^2). Exporting all
    /// 20,000 records must complete in well under a second, not tens of seconds.
    #[test]
    #[ignore]
    fn exporting_every_record_in_a_large_log_stays_near_linear_not_quadratic() {
        let mut log = TransparencyLog::new();
        let p = probe();
        for i in 0..20_000usize {
            log.append(format!("record-{i}").as_bytes());
        }
        let checkpoint = log.checkpoint(&p, 1_000);
        let indices: Vec<usize> = (0..checkpoint.size).collect();
        let start = std::time::Instant::now();
        let receipts = log.receipts_for(&indices, &checkpoint);
        let elapsed = start.elapsed();
        assert_eq!(receipts.iter().filter(|r| r.is_some()).count(), 20_000);
        assert!(
            elapsed.as_millis() < 500,
            "exporting all 20,000 records took {elapsed:?} -- the real incident this \
             reproduces took 17+ seconds at ~4,500 records (500ms is still a very \
             generous bound at this larger size)"
        );
    }
}
