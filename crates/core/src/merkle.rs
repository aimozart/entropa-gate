//! RFC 6962-style Merkle tree primitives — see `a stage record (not published)`.
//! Pure functions only: no I/O, no `Chain`/`Node` coupling, so a leaf's inclusion or a
//! tree's append-only consistency can be independently verified by anyone, without
//! trusting this project's own verification code.
//!
//! Deliberate deviation from RFC 6962's wire format: an inclusion proof here is a list
//! of `(sibling, side)` pairs rather than bare hashes, so verification never needs to
//! recompute tree-shape splits — it's a documented simplification for our own internal
//! use, not a claim of interop with existing CT tooling.

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// A node/leaf digest. blake3, matching the rest of `entropa-core`.
pub type Hash = [u8; 32];

/// Domain-separated leaf hash — never collides with a node hash over the same bytes.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Domain-separated internal-node hash.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// The largest power of two strictly less than `n` — RFC 6962's tree-split point.
/// Only called with `n >= 2`. `pub(crate)` so `transparency_log`'s memoized batch
/// proof builder can reuse the exact same tree-split logic as `root`/`inclusion_proof`
/// below, rather than risking a second, subtly different implementation that could
/// produce a different (and therefore mismatched) tree shape.
pub(crate) fn largest_power_of_two_less_than(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The Merkle root over `leaves`, or `None` for an empty input. A single leaf's root is
/// its own leaf hash — no further hashing needed for a one-element tree.
pub fn root(leaves: &[Hash]) -> Option<Hash> {
    match leaves.len() {
        0 => None,
        1 => Some(leaves[0]),
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = root(&leaves[..k])?;
            let right = root(&leaves[k..])?;
            Some(node_hash(&left, &right))
        }
    }
}

/// Which side of the current node a proof step's sibling sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Side {
    /// The sibling is the left child.
    Left,
    /// The sibling is the right child.
    Right,
}

/// One step of an inclusion proof: a sibling hash and which side it's on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofStep {
    /// The sibling node's hash.
    #[serde(with = "hex_hash")]
    pub sibling: Hash,
    /// Which side of the current node the sibling sits on.
    pub side: Side,
}

/// Serializes a [`type@Hash`] as a hex string instead of a raw byte array, matching this
/// project's existing hash-formatting convention throughout the JSON API.
pub mod hex_hash {
    use super::Hash;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serde `serialize_with` hook: write a [`type@Hash`] as lowercase hex.
    pub fn serialize<S: Serializer>(hash: &Hash, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(hash))
    }

    /// Serde `deserialize_with` hook: read a [`type@Hash`] from hex; wrong length or bad hex is an error.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Hash, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected a 32-byte hex string"))
    }
}

/// The audit path proving `leaves[index]` is under `root(leaves)`. `None` if `index` is
/// out of range or `leaves` is empty.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Option<Vec<ProofStep>> {
    fn go(leaves: &[Hash], index: usize, proof: &mut Vec<ProofStep>) -> bool {
        match leaves.len() {
            0 => false,
            1 => index == 0,
            n => {
                let k = largest_power_of_two_less_than(n);
                if index < k {
                    let ok = go(&leaves[..k], index, proof);
                    if ok {
                        if let Some(sibling) = root(&leaves[k..]) {
                            proof.push(ProofStep {
                                sibling,
                                side: Side::Right,
                            });
                        }
                    }
                    ok
                } else {
                    let ok = go(&leaves[k..], index - k, proof);
                    if ok {
                        if let Some(sibling) = root(&leaves[..k]) {
                            proof.push(ProofStep {
                                sibling,
                                side: Side::Left,
                            });
                        }
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
    go(leaves, index, &mut proof).then_some(proof)
}

/// Verify an inclusion proof for `leaf` against `expected_root`. Self-contained — no
/// access to the full tree or even the tree's size is needed, only the proof itself.
/// **It does not bind the leaf's position or the tree size**; use [`verify_inclusion_at`]
/// when the claimed index and size matter (receipts do).
pub fn verify_inclusion(leaf: &Hash, proof: &[ProofStep], expected_root: &Hash) -> bool {
    let mut current = *leaf;
    for step in proof {
        current = match step.side {
            Side::Left => node_hash(&step.sibling, &current),
            Side::Right => node_hash(&current, &step.sibling),
        };
    }
    &current == expected_root
}

/// Verify an inclusion proof **bound to a position and a tree size** (RFC 6962 / RFC 9162
/// inclusion verification). Unlike [`verify_inclusion`], which only checks that the hashes
/// combine to the root, this also derives from `index` and `tree_size` which side every
/// sibling must be on and how many steps the path must have, so a proof only verifies for
/// the one `index` it was built for and for the tree size it was built against.
/// `proof` is ordered from the leaf upward, as produced by [`inclusion_proof`].
pub fn verify_inclusion_at(
    leaf: &Hash,
    index: usize,
    tree_size: usize,
    proof: &[ProofStep],
    expected_root: &Hash,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let (mut fnode, mut snode) = (index, tree_size - 1);
    let mut current = *leaf;
    for step in proof {
        if snode == 0 {
            return false; // proof longer than the path for this index and size
        }
        let sibling_on_left = fnode & 1 == 1 || fnode == snode;
        let expected_side = if sibling_on_left {
            Side::Left
        } else {
            Side::Right
        };
        if step.side != expected_side {
            return false;
        }
        if sibling_on_left {
            current = node_hash(&step.sibling, &current);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            current = node_hash(&current, &step.sibling);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && &current == expected_root
}

/// A proof that the tree at `new_size` is a strict append-only extension of the tree at
/// `old_size` — the actual "nothing was rewritten" property. `None` if `old_size` is 0
/// or greater than `new_size` (= `leaves.len()`).
pub fn consistency_proof(leaves: &[Hash], old_size: usize) -> Option<Vec<Hash>> {
    let new_size = leaves.len();
    if old_size == 0 || old_size > new_size {
        return None;
    }
    let mut proof = Vec::new();
    subproof(leaves, old_size, new_size, true, &mut proof);
    Some(proof)
}

fn subproof(leaves: &[Hash], m: usize, n: usize, starting_boundary: bool, proof: &mut Vec<Hash>) {
    if m == n {
        if !starting_boundary {
            if let Some(r) = root(leaves) {
                proof.push(r);
            }
        }
        return;
    }
    let k = largest_power_of_two_less_than(n);
    if m <= k {
        subproof(&leaves[..k], m, k, starting_boundary, proof);
        if let Some(r) = root(&leaves[k..]) {
            proof.push(r);
        }
    } else {
        subproof(&leaves[k..], m - k, n - k, false, proof);
        if let Some(l) = root(&leaves[..k]) {
            proof.push(l);
        }
    }
}

/// Verify a consistency proof: does `new_root` (at `new_size`) genuinely extend
/// `old_root` (at `old_size`) with only appends, no rewrite? Mirrors `subproof`'s exact
/// recursive structure so both sides agree on tree shape by construction.
pub fn verify_consistency(
    old_root: &Hash,
    old_size: usize,
    new_root: &Hash,
    new_size: usize,
    proof: &[Hash],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    let mut idx = 0;
    let result = verify_subproof(old_root, old_size, new_size, true, proof, &mut idx);
    match result {
        Some((computed_old, computed_new)) => {
            idx == proof.len() && &computed_old == old_root && &computed_new == new_root
        }
        None => false,
    }
}

/// Returns `(old_subtree_root, new_subtree_root)` reconstructed from the proof, walking
/// the identical decomposition `subproof` used to generate it.
fn verify_subproof(
    old_root: &Hash,
    m: usize,
    n: usize,
    starting_boundary: bool,
    proof: &[Hash],
    idx: &mut usize,
) -> Option<(Hash, Hash)> {
    if m == n {
        if starting_boundary {
            Some((*old_root, *old_root))
        } else {
            let node = *proof.get(*idx)?;
            *idx += 1;
            Some((node, node))
        }
    } else {
        let k = largest_power_of_two_less_than(n);
        if m <= k {
            let (o, new_left) = verify_subproof(old_root, m, k, starting_boundary, proof, idx)?;
            let right = *proof.get(*idx)?;
            *idx += 1;
            Some((o, node_hash(&new_left, &right)))
        } else {
            let (o, new_right) = verify_subproof(old_root, m - k, n - k, false, proof, idx)?;
            let left = *proof.get(*idx)?;
            *idx += 1;
            Some((node_hash(&left, &o), node_hash(&left, &new_right)))
        }
    }
}

#[cfg(test)]
mod tests {
    fn leaves_of(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(format!("l{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn verify_inclusion_at_accepts_every_index_of_every_size_and_only_that_index() {
        for n in 1..=33 {
            let leaves = leaves_of(n);
            let r = root(&leaves).unwrap();
            for i in 0..n {
                let proof = inclusion_proof(&leaves, i).unwrap();
                assert!(
                    verify_inclusion_at(&leaves[i], i, n, &proof, &r),
                    "n={n} i={i}"
                );
                for j in 0..n + 2 {
                    if j != i {
                        assert!(
                            !verify_inclusion_at(&leaves[i], j, n, &proof, &r),
                            "n={n} i={i} claimed {j}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn verify_inclusion_at_rejects_a_wrong_tree_size_even_when_the_hashes_combine() {
        let leaves = leaves_of(4);
        let r = root(&leaves).unwrap();
        let proof = inclusion_proof(&leaves, 1).unwrap();
        // Sizes with a different audit-path shape for index 1; size 3 has the SAME shape as size 4,
        // so a path alone cannot distinguish it (the signature over (root, size) binds the size).
        // See docs/adr/0016.
        for wrong in [0usize, 1, 2, 5, 8] {
            assert!(
                !verify_inclusion_at(&leaves[1], 1, wrong, &proof, &r),
                "size {wrong}"
            );
        }
    }

    #[test]
    fn verify_inclusion_at_rejects_a_flipped_side_or_extra_or_missing_steps() {
        let leaves = leaves_of(6);
        let r = root(&leaves).unwrap();
        let proof = inclusion_proof(&leaves, 4).unwrap();
        let mut flipped = proof.clone();
        flipped[0].side = if flipped[0].side == Side::Left {
            Side::Right
        } else {
            Side::Left
        };
        assert!(!verify_inclusion_at(&leaves[4], 4, 6, &flipped, &r));
        let mut longer = proof.clone();
        longer.push(proof[0]);
        assert!(!verify_inclusion_at(&leaves[4], 4, 6, &longer, &r));
        assert!(!verify_inclusion_at(
            &leaves[4],
            4,
            6,
            &proof[..proof.len() - 1],
            &r
        ));
        assert!(
            !verify_inclusion_at(&leaves[0], 0, 0, &[], &r),
            "empty tree"
        );
    }

    #[test]
    fn a_single_leaf_tree_has_an_empty_proof_at_index_zero_only() {
        let leaves = leaves_of(1);
        let r = root(&leaves).unwrap();
        assert!(verify_inclusion_at(&leaves[0], 0, 1, &[], &r));
        assert!(!verify_inclusion_at(&leaves[0], 1, 1, &[], &r));
    }

    #[test]
    fn verify_consistency_rejects_a_zero_or_larger_old_size_even_with_an_empty_proof() {
        let r = leaf_hash(b"x");
        assert!(!verify_consistency(&r, 0, &r, 1, &[]), "old_size 0");
        assert!(
            !verify_consistency(&r, 2, &r, 1, &[]),
            "old_size > new_size"
        );
        assert!(
            verify_consistency(&r, 1, &r, 1, &[]),
            "equal sizes, same root"
        );
    }

    use super::*;

    fn leaves_from(strs: &[&str]) -> Vec<Hash> {
        strs.iter().map(|s| leaf_hash(s.as_bytes())).collect()
    }

    #[test]
    fn single_leaf_root_is_its_own_leaf_hash() {
        let leaves = leaves_from(&["a"]);
        assert_eq!(root(&leaves), Some(leaves[0]));
    }

    #[test]
    fn empty_tree_has_no_root() {
        let leaves: Vec<Hash> = Vec::new();
        assert_eq!(root(&leaves), None);
    }

    #[test]
    fn root_is_deterministic() {
        let leaves = leaves_from(&["a", "b", "c", "d", "e"]);
        assert_eq!(root(&leaves), root(&leaves));
    }

    #[test]
    fn root_changes_if_any_leaf_changes() {
        let leaves_a = leaves_from(&["a", "b", "c"]);
        let leaves_b = leaves_from(&["a", "b", "x"]);
        assert_ne!(root(&leaves_a), root(&leaves_b));
    }

    #[test]
    fn leaf_hash_and_node_hash_are_domain_separated() {
        // A leaf hash must never collide with a node hash over the same bytes -- this is
        // the exact ambiguity that broke early (pre-RFC-6962) Merkle tree designs.
        let l = leaf_hash(b"same-bytes-either-way");
        let n = node_hash(&l, &l);
        assert_ne!(l, n);
    }

    #[test]
    fn inclusion_proof_verifies_for_every_index_in_a_real_tree() {
        let leaves = leaves_from(&["a", "b", "c", "d", "e", "f", "g"]);
        let expected_root = root(&leaves).unwrap();
        for i in 0..leaves.len() {
            let proof = inclusion_proof(&leaves, i).expect("valid index must produce a proof");
            assert!(
                verify_inclusion(&leaves[i], &proof, &expected_root),
                "index {i} must verify"
            );
        }
    }

    #[test]
    fn inclusion_proof_out_of_range_index_is_none() {
        let leaves = leaves_from(&["a", "b", "c"]);
        assert_eq!(inclusion_proof(&leaves, 3), None);
    }

    #[test]
    fn inclusion_proof_rejects_a_forged_leaf() {
        let leaves = leaves_from(&["a", "b", "c", "d"]);
        let expected_root = root(&leaves).unwrap();
        let proof = inclusion_proof(&leaves, 2).unwrap();
        let forged_leaf = leaf_hash(b"not-actually-in-the-tree");
        assert!(!verify_inclusion(&forged_leaf, &proof, &expected_root));
    }

    #[test]
    fn inclusion_proof_rejects_a_tampered_sibling() {
        let leaves = leaves_from(&["a", "b", "c", "d"]);
        let expected_root = root(&leaves).unwrap();
        let mut proof = inclusion_proof(&leaves, 1).unwrap();
        proof[0].sibling = leaf_hash(b"tampered");
        assert!(!verify_inclusion(&leaves[1], &proof, &expected_root));
    }

    #[test]
    fn inclusion_proof_rejects_the_wrong_root() {
        let leaves = leaves_from(&["a", "b", "c", "d"]);
        let proof = inclusion_proof(&leaves, 0).unwrap();
        let wrong_root = leaf_hash(b"wrong");
        assert!(!verify_inclusion(&leaves[0], &proof, &wrong_root));
    }

    #[test]
    fn consistency_proof_round_trips_across_many_size_pairs() {
        let all = leaves_from(&[
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
        ]);
        for old_size in 1..=all.len() {
            for new_size in old_size..=all.len() {
                let old_leaves = &all[..old_size];
                let new_leaves = &all[..new_size];
                let old_root = root(old_leaves).unwrap();
                let new_root = root(new_leaves).unwrap();
                let proof = consistency_proof(new_leaves, old_size)
                    .expect("old_size <= new_size must produce a proof");
                assert!(
                    verify_consistency(&old_root, old_size, &new_root, new_size, &proof),
                    "old_size={old_size} new_size={new_size} must verify"
                );
            }
        }
    }

    #[test]
    fn consistency_proof_rejects_a_history_rewrite_after_the_checkpoint() {
        // The actual point of this whole primitive: once a checkpoint (old_root at
        // old_size) is published, nobody -- not even the operator -- should be able to
        // silently replace what comes after it and have the result still verify.
        let real_history = leaves_from(&["a", "b", "c", "d", "e"]);
        let old_size = 3;
        let old_root = root(&real_history[..old_size]).unwrap();

        let proof = consistency_proof(&real_history, old_size).unwrap();
        let real_new_root = root(&real_history).unwrap();
        assert!(verify_consistency(
            &old_root,
            old_size,
            &real_new_root,
            real_history.len(),
            &proof
        ));

        // Now imagine the last two "real" leaves were swapped for different content and
        // the tree rebuilt -- a rewrite. The proof generated against real history must
        // not verify against this rewritten root.
        let mut rewritten_history = real_history[..old_size].to_vec();
        rewritten_history.extend(leaves_from(&["x", "y"]));
        let rewritten_root = root(&rewritten_history).unwrap();
        assert!(!verify_consistency(
            &old_root,
            old_size,
            &rewritten_root,
            rewritten_history.len(),
            &proof
        ));
    }

    #[test]
    fn consistency_proof_rejects_a_tampered_old_root() {
        let leaves = leaves_from(&["a", "b", "c", "d", "e"]);
        let real_old_root = root(&leaves[..2]).unwrap();
        let new_root = root(&leaves).unwrap();
        let proof = consistency_proof(&leaves, 2).unwrap();
        let wrong_old_root = leaf_hash(b"wrong");
        assert!(!verify_consistency(
            &wrong_old_root,
            2,
            &new_root,
            leaves.len(),
            &proof
        ));
        // sanity: the real one does verify, so this isn't just a broken test
        assert!(verify_consistency(
            &real_old_root,
            2,
            &new_root,
            leaves.len(),
            &proof
        ));
    }

    #[test]
    fn consistency_proof_at_equal_sizes_is_empty_and_requires_matching_roots() {
        let leaves = leaves_from(&["a", "b", "c"]);
        let r = root(&leaves).unwrap();
        let proof = consistency_proof(&leaves, leaves.len()).unwrap();
        assert!(proof.is_empty());
        assert!(verify_consistency(
            &r,
            leaves.len(),
            &r,
            leaves.len(),
            &proof
        ));
    }

    #[test]
    fn consistency_proof_with_old_size_greater_than_new_size_is_none() {
        let leaves = leaves_from(&["a", "b", "c"]);
        assert_eq!(consistency_proof(&leaves, 5), None);
    }

    #[test]
    fn consistency_proof_with_zero_old_size_is_none() {
        let leaves = leaves_from(&["a", "b", "c"]);
        assert_eq!(consistency_proof(&leaves, 0), None);
    }

    /// Real, measured evidence for `a stage record (not published)`'s comparison
    /// table -- not an assumption. An inclusion proof's length must grow logarithmically
    /// with tree size, not linearly: this is the actual, quantifiable reason a customer's
    /// verification cost stays cheap as the log grows, unlike walking a linear chain.
    #[test]
    fn inclusion_proof_length_grows_logarithmically_not_linearly() {
        for &n in &[10usize, 100, 1_000, 10_000, 100_000] {
            let leaves: Vec<Hash> = (0..n)
                .map(|i| leaf_hash(format!("record-{i}").as_bytes()))
                .collect();
            let proof = inclusion_proof(&leaves, n / 2).unwrap();
            let max_expected = (n as f64).log2().ceil() as usize + 1;
            assert!(
                proof.len() <= max_expected,
                "n={n}: proof length {} exceeds ceil(log2(n))+1={max_expected} -- \
                 this is supposed to stay logarithmic, not track tree size",
                proof.len()
            );
            println!(
                "n={n:>7}  proof_len={:>2}  (vs. walking all {n} records for a linear chain)",
                proof.len()
            );
        }
    }
}
