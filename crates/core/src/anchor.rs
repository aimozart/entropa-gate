//! INS2 slice 1 (docs/THREAT-MODEL-OPERATOR.md): checkpoint v2 (counter and a link to the previous checkpoint), outside anchors, and the verifier's closed result with a fixed precedence.
//! Pure functions over parsed data: no files, no network, no clock, no randomness.
use crate::merkle::Hash;
use crate::signer::{CheckpointSigner, SignError};
use crate::transparency_log::Checkpoint;

/// The domain tag at the start of every v2 checkpoint digest.
pub const V2_DOMAIN: &[u8] = b"entropa-checkpoint-v2\0";

/// A v2 checkpoint: the v1 fields plus a counter and the chain digest of the previous checkpoint (all zero for the first).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointV2 {
    /// 1 for the first checkpoint, then +1 for each (also when the size is unchanged).
    pub counter: u64,
    /// `chain_digest` of the previous checkpoint; zero for the first.
    #[serde(with = "crate::merkle::hex_hash")]
    pub prev: Hash,
    /// Merkle root at `size`.
    #[serde(with = "crate::merkle::hex_hash")]
    pub root: Hash,
    /// Records covered.
    pub size: usize,
    /// Caller-supplied time, signed.
    pub timestamp: u64,
    /// Hex ML-DSA verifying key of the signer.
    pub proposer_pubkey: String,
    /// Hex ML-DSA signature over [`digest_v2`].
    pub signature: String,
}

/// Either kind of checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyCheckpoint {
    /// Signs root, size and time only (no rollback protection).
    V1(Checkpoint),
    /// Signs a domain tag, a counter, the previous digest, root, size and time.
    V2(CheckpointV2),
}

/// The bytes a v2 checkpoint signs: domain tag, counter, previous digest, root, size, time (big-endian integers).
pub fn digest_v2(counter: u64, prev: &Hash, root: &Hash, size: usize, timestamp: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(V2_DOMAIN.len() + 8 + 32 + 32 + 8 + 8);
    d.extend_from_slice(V2_DOMAIN);
    d.extend_from_slice(&counter.to_be_bytes());
    d.extend_from_slice(prev);
    d.extend_from_slice(root);
    d.extend_from_slice(&(size as u64).to_be_bytes());
    d.extend_from_slice(&timestamp.to_be_bytes());
    d
}

impl CheckpointV2 {
    /// The digest that this checkpoint's signature covers.
    pub fn digest(&self) -> Vec<u8> {
        digest_v2(
            self.counter,
            &self.prev,
            &self.root,
            self.size,
            self.timestamp,
        )
    }
    /// The hash the NEXT checkpoint carries as `prev`: it covers the signed bytes and the signature.
    pub fn chain_digest(&self) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"entropa-checkpoint-chain-v2\0");
        h.update(&self.digest());
        h.update(self.signature.as_bytes());
        *h.finalize().as_bytes()
    }
    /// Does the signature verify under `expected_pubkey_hex`, and is that the key the checkpoint claims?
    pub fn verify_signature(&self, expected_pubkey_hex: &str) -> bool {
        self.proposer_pubkey == expected_pubkey_hex
            && crate::pqc::verify_hex(expected_pubkey_hex, &self.digest(), &self.signature)
    }
}

/// Sign a v2 checkpoint through any signer. The signature is checked under the signer's own key before it is returned.
pub fn sign_v2<S: CheckpointSigner>(
    signer: &S,
    counter: u64,
    prev: &Hash,
    root: &Hash,
    size: usize,
    timestamp: u64,
) -> Result<CheckpointV2, SignError> {
    let digest = digest_v2(counter, prev, root, size, timestamp);
    let signature = signer.try_sign_hex(&digest)?;
    let pubkey = signer.pubkey_hex();
    if !crate::pqc::verify_hex(&pubkey, &digest, &signature) {
        return Err(SignError::Backend(
            "signature does not verify under the signer's public key".into(),
        ));
    }
    Ok(CheckpointV2 {
        counter,
        prev: *prev,
        root: *root,
        size,
        timestamp,
        proposer_pubkey: pubkey,
        signature,
    })
}

/// What an outside holder keeps: hash-only (size, root, optional counter) and, better, the signed checkpoint itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// Records covered.
    pub size: usize,
    /// Root at `size`.
    pub root: Hash,
    /// v2 counter, when known.
    pub counter: Option<u64>,
    /// The signed checkpoint the anchor was made from, when kept.
    pub signed: Option<AnyCheckpoint>,
}

/// The verifier's closed result. `assess` never returns `FormatError` (the reader raises it before parsing succeeds and it always wins).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The input could not be parsed (raised by the reader).
    FormatError,
    /// A checkpoint's signature does not verify under the key it claims.
    SignatureInvalid,
    /// A checkpoint is validly signed by a key other than the expected one, with no rotation record.
    KeyChangedUnlogged,
    /// Checkpoints and records disagree (root, size, chain or counter).
    CheckpointMismatch,
    /// The key signed two different roots for one size or counter.
    ForkDetected,
    /// A hash-only anchor's root differs from the root recomputed at its size.
    RewrittenSinceAnchor,
    /// The ledger is older or shorter than an anchor.
    RolledBack,
    /// A higher counter carries an earlier time.
    ClockRegression,
    /// The install expects an anchor and none is given.
    AnchorMissing,
    /// Consistent with an anchor of this size; says nothing about records after it.
    OkAnchored(usize),
    /// Verified, and no outside copy exists to compare with.
    OkUnanchored,
}

impl Verdict {
    /// The closed code string.
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::FormatError => "format_error",
            Verdict::SignatureInvalid => "signature_invalid",
            Verdict::KeyChangedUnlogged => "key_changed_unlogged",
            Verdict::CheckpointMismatch => "checkpoint_mismatch",
            Verdict::ForkDetected => "fork_detected",
            Verdict::RewrittenSinceAnchor => "rewritten_since_anchor",
            Verdict::RolledBack => "rolled_back",
            Verdict::ClockRegression => "clock_regression",
            Verdict::AnchorMissing => "anchor_missing",
            Verdict::OkAnchored(_) => "ok_anchored",
            Verdict::OkUnanchored => "ok_unanchored",
        }
    }
}

impl AnyCheckpoint {
    fn size(&self) -> usize {
        match self {
            AnyCheckpoint::V1(c) => c.size,
            AnyCheckpoint::V2(c) => c.size,
        }
    }
    fn root(&self) -> Hash {
        match self {
            AnyCheckpoint::V1(c) => c.root,
            AnyCheckpoint::V2(c) => c.root,
        }
    }
    fn pubkey(&self) -> &str {
        match self {
            AnyCheckpoint::V1(c) => &c.proposer_pubkey,
            AnyCheckpoint::V2(c) => &c.proposer_pubkey,
        }
    }
    /// The signature verifies under the key the checkpoint itself claims.
    fn valid_under_own_key(&self) -> bool {
        match self {
            AnyCheckpoint::V1(c) => c.verify_signature(&c.proposer_pubkey),
            AnyCheckpoint::V2(c) => c.verify_signature(&c.proposer_pubkey),
        }
    }
    fn counter(&self) -> Option<u64> {
        match self {
            AnyCheckpoint::V1(_) => None,
            AnyCheckpoint::V2(c) => Some(c.counter),
        }
    }
}

/// The root over the first `size` leaves (the empty log reports the hash of the empty leaf, as the log does).
fn root_at(leaves: &[Hash], size: usize) -> Option<Hash> {
    if size > leaves.len() {
        return None;
    }
    Some(crate::merkle::root(&leaves[..size]).unwrap_or_else(|| crate::merkle::leaf_hash(b"")))
}

/// The v2 checkpoints form one chain: counters 1, 2, 3.. with each `prev` equal to the chain digest of the one before (zero for the first).
fn chain_ok(cps: &[AnyCheckpoint]) -> bool {
    // a ledger may start v1 and continue v2 (the v2 chain starts at the switch: counter 1, previous digest zero); once a v2 checkpoint exists a v1 one may not follow (a downgrade)
    let mut last: Option<&CheckpointV2> = None;
    for c in cps {
        match c {
            AnyCheckpoint::V1(_) => {
                if last.is_some() {
                    return false;
                }
            }
            AnyCheckpoint::V2(c) => {
                let (want_counter, want_prev) = match last {
                    None => (1, [0u8; 32]),
                    Some(p) => (p.counter + 1, p.chain_digest()),
                };
                if c.counter != want_counter || c.prev != want_prev {
                    return false;
                }
                last = Some(c);
            }
        }
    }
    true
}

fn clock_ok(cps: &[AnyCheckpoint]) -> bool {
    let mut last = 0u64;
    for c in cps {
        if let AnyCheckpoint::V2(c) = c {
            if c.timestamp < last {
                return false;
            }
            last = c.timestamp;
        }
    }
    true
}

/// The verifier. Precedence (the first that applies wins): format_error, signature_invalid, key_changed_unlogged, checkpoint_mismatch, fork_detected,
/// rewritten_since_anchor, rolled_back, clock_regression, anchor_missing, then ok_anchored(N) or ok_unanchored.
pub fn assess(
    leaves: &[Hash],
    checkpoints: &[AnyCheckpoint],
    anchors: &[Anchor],
    expected_pubkey_hex: &str,
    expect_anchor: bool,
) -> Verdict {
    if checkpoints.iter().any(|c| !c.valid_under_own_key()) {
        return Verdict::SignatureInvalid;
    }
    if checkpoints
        .iter()
        .any(|c| c.pubkey() != expected_pubkey_hex)
    {
        return Verdict::KeyChangedUnlogged;
    }
    // records and checkpoints agree: every checkpoint's root is the root of its prefix, sizes never shrink, the last covers exactly the records present, the v2 chain is intact
    let mut prev_size = 0usize;
    for c in checkpoints {
        if c.size() < prev_size || root_at(leaves, c.size()) != Some(c.root()) {
            return Verdict::CheckpointMismatch;
        }
        prev_size = c.size();
    }
    if checkpoints.last().map_or(0, AnyCheckpoint::size) != leaves.len() || !chain_ok(checkpoints) {
        return Verdict::CheckpointMismatch;
    }
    let signed_anchor = |a: &Anchor| -> Option<AnyCheckpoint> {
        a.signed
            .clone()
            .filter(|s| s.valid_under_own_key() && s.pubkey() == expected_pubkey_hex)
    };
    // fork: a validly signed anchor and a validly signed checkpoint of the ledger disagree at one size (or one counter)
    for a in anchors {
        if let Some(s) = signed_anchor(a) {
            for c in checkpoints {
                // one size, or one counter: either way the key signed two roots for one slot
                let same_slot = s.size() == c.size()
                    || matches!((s.counter(), c.counter()), (Some(x), Some(y)) if x == y);
                if same_slot && s.root() != c.root() {
                    return Verdict::ForkDetected;
                }
            }
        }
    }
    for a in anchors {
        if a.size <= leaves.len() && root_at(leaves, a.size) != Some(a.root) {
            return Verdict::RewrittenSinceAnchor;
        }
    }
    let last_counter = checkpoints.iter().rev().find_map(AnyCheckpoint::counter);
    for a in anchors {
        let shorter = leaves.len() < a.size;
        let older = matches!((a.counter, last_counter), (Some(ac), Some(lc)) if lc < ac);
        if shorter || older {
            return Verdict::RolledBack;
        }
    }
    if !clock_ok(checkpoints) {
        return Verdict::ClockRegression;
    }
    match anchors.iter().map(|a| a.size).max() {
        Some(n) => Verdict::OkAnchored(n),
        None if expect_anchor => Verdict::AnchorMissing,
        None => Verdict::OkUnanchored,
    }
}
