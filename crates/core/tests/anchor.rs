//! INS2 slice 1 red tests (docs/THREAT-MODEL-OPERATOR.md, section 4 and the precedence list): checkpoint v2 and the verifier's closed result, one test per attack class and column, plus pairs that trip two conditions at once.
//! Ledgers are planted in memory from fixed test seeds (public test values). Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::anchor::*;
use entropa_core::merkle::{self, Hash};
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::Probe;
use proptest::prelude::*;

fn probe(b: u8) -> Probe {
    Probe::from_signing_key_hex(&hex::encode([b; 32])).unwrap()
}
fn recs(tag: &str, n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("{tag}-record-{i}").into_bytes())
        .collect()
}
fn lv(r: &[Vec<u8>]) -> Vec<Hash> {
    r.iter().map(|x| merkle::leaf_hash(x)).collect()
}
fn v1(p: &Probe, r: &[Vec<u8>], size: usize, ts: u64) -> AnyCheckpoint {
    let mut log = TransparencyLog::new();
    for x in &r[..size] {
        log.append(x);
    }
    AnyCheckpoint::V1(log.checkpoint(p, ts))
}
/// A chain of v2 checkpoints at the given sizes and times, counters 1.., each linked to the previous one.
fn chain(p: &Probe, leaves: &[Hash], sizes: &[usize], times: &[u64]) -> Vec<AnyCheckpoint> {
    let mut prev = [0u8; 32];
    let mut out = vec![];
    for (i, (s, t)) in sizes.iter().zip(times).enumerate() {
        let root = merkle::root(&leaves[..*s]).unwrap();
        let cp = sign_v2(p, i as u64 + 1, &prev, &root, *s, *t).unwrap();
        prev = cp.chain_digest();
        out.push(AnyCheckpoint::V2(cp));
    }
    out
}
fn anchor(cp: &AnyCheckpoint, signed: bool) -> Anchor {
    let (size, root, counter) = match cp {
        AnyCheckpoint::V1(c) => (c.size, c.root, None),
        AnyCheckpoint::V2(c) => (c.size, c.root, Some(c.counter)),
    };
    Anchor {
        size,
        root,
        counter,
        signed: signed.then(|| cp.clone()),
    }
}
fn pk(p: &Probe) -> String {
    p.pubkey_hex()
}
fn flip(h: &str) -> String {
    let mut b = h.as_bytes().to_vec();
    b[10] = if b[10] == b'0' { b'1' } else { b'0' };
    String::from_utf8(b).unwrap()
}

/// The honest ledger every attack starts from: 10 records, v2 checkpoints at sizes 3, 6, 10 and times 100, 200, 300.
struct Honest {
    p: Probe,
    recs: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
    cps: Vec<AnyCheckpoint>,
}
fn honest() -> Honest {
    let p = probe(1);
    let r = recs("orig", 10);
    let l = lv(&r);
    let cps = chain(&p, &l, &[3, 6, 10], &[100, 200, 300]);
    Honest {
        p,
        recs: r,
        leaves: l,
        cps,
    }
}

// ---- the format of v2 and its pieces
#[test]
fn a1_the_v2_digest_matches_an_independent_python_derivation() {
    // python: b"entropa-checkpoint-v2\0" + be64(3) + [1]*32 + [2]*32 + be64(7) + be64(1800000000)
    let want = "656e74726f70612d636865636b706f696e742d7632000000000000000003010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000007000000006b49d200";
    let got = digest_v2(3, &[1u8; 32], &[2u8; 32], 7, 1_800_000_000);
    assert_eq!(hex::encode(got), want);
}
#[test]
fn a2_sign_verify_and_the_chain_digest_binds_every_field() {
    let h = honest();
    let AnyCheckpoint::V2(c) = &h.cps[1] else {
        panic!()
    };
    assert!(c.verify_signature(&pk(&h.p)));
    assert!(!c.verify_signature(&pk(&probe(2))), "another key");
    for tweak in 0..5 {
        let mut d = c.clone();
        match tweak {
            0 => d.counter += 1,
            1 => d.prev[0] ^= 1,
            2 => d.root[0] ^= 1,
            3 => d.size += 1,
            _ => d.timestamp += 1,
        }
        assert!(!d.verify_signature(&pk(&h.p)), "field {tweak} is signed");
    }
    assert_ne!(c.chain_digest(), [0u8; 32]);
    let mut s = c.clone();
    s.signature = flip(&s.signature);
    assert_ne!(
        s.chain_digest(),
        c.chain_digest(),
        "the chain digest covers the signature too"
    );
}
#[test]
fn a3_the_closed_codes_are_exactly_these_strings() {
    let all = [
        (Verdict::FormatError, "format_error"),
        (Verdict::SignatureInvalid, "signature_invalid"),
        (Verdict::KeyChangedUnlogged, "key_changed_unlogged"),
        (Verdict::CheckpointMismatch, "checkpoint_mismatch"),
        (Verdict::ForkDetected, "fork_detected"),
        (Verdict::RewrittenSinceAnchor, "rewritten_since_anchor"),
        (Verdict::RolledBack, "rolled_back"),
        (Verdict::ClockRegression, "clock_regression"),
        (Verdict::AnchorMissing, "anchor_missing"),
        (Verdict::OkAnchored(6), "ok_anchored"),
        (Verdict::OkUnanchored, "ok_unanchored"),
    ];
    for (v, s) in all {
        assert_eq!(v.code(), s);
    }
}

// ---- unchanged ledgers
#[test]
fn b1_an_unchanged_ledger_is_ok_unanchored_without_an_anchor_and_anchor_missing_when_one_is_expected(
) {
    let h = honest();
    assert_eq!(
        assess(&h.leaves, &h.cps, &[], &pk(&h.p), false),
        Verdict::OkUnanchored
    );
    assert_eq!(
        assess(&h.leaves, &h.cps, &[], &pk(&h.p), true),
        Verdict::AnchorMissing
    );
    let v1cps = vec![v1(&h.p, &h.recs, 4, 10), v1(&h.p, &h.recs, 10, 20)];
    assert_eq!(
        assess(&h.leaves, &v1cps, &[], &pk(&h.p), false),
        Verdict::OkUnanchored,
        "v1 ledgers keep verifying"
    );
}
#[test]
fn b2_an_older_anchor_hash_only_or_signed_gives_ok_anchored_with_its_size() {
    let h = honest();
    for signed in [false, true] {
        let a = anchor(&h.cps[1], signed);
        assert_eq!(
            assess(&h.leaves, &h.cps, &[a], &pk(&h.p), true),
            Verdict::OkAnchored(6)
        );
    }
    let both = [anchor(&h.cps[0], false), anchor(&h.cps[1], true)];
    assert_eq!(
        assess(&h.leaves, &h.cps, &both, &pk(&h.p), false),
        Verdict::OkAnchored(6),
        "the largest anchored size"
    );
}

// ---- the attack classes (threat model section 4)
fn alt_ledger(h: &Honest) -> (Vec<Hash>, Vec<AnyCheckpoint>) {
    let l = lv(&recs("alt", 10));
    let c = chain(&h.p, &l, &[3, 6, 10], &[100, 200, 300]);
    (l, c)
}
#[test]
fn c1_a1_rewrite_and_resign_is_invisible_without_an_anchor_and_caught_with_one() {
    let h = honest();
    let (l, c) = alt_ledger(&h);
    assert_eq!(
        assess(&l, &c, &[], &pk(&h.p), false),
        Verdict::OkUnanchored,
        "the known undetectable case"
    );
    assert_eq!(
        assess(&l, &c, &[anchor(&h.cps[1], false)], &pk(&h.p), false),
        Verdict::RewrittenSinceAnchor
    );
    assert_eq!(
        assess(&l, &c, &[anchor(&h.cps[1], true)], &pk(&h.p), false),
        Verdict::ForkDetected,
        "two signed roots for one size"
    );
}
#[test]
fn c2_a2_a3_a_shorter_or_older_ledger_is_rolled_back_with_any_anchor() {
    let h = honest();
    let older = (h.leaves[..6].to_vec(), h.cps[..2].to_vec());
    assert_eq!(
        assess(&older.0, &older.1, &[], &pk(&h.p), false),
        Verdict::OkUnanchored
    );
    for signed in [false, true] {
        assert_eq!(
            assess(
                &older.0,
                &older.1,
                &[anchor(&h.cps[2], signed)],
                &pk(&h.p),
                false
            ),
            Verdict::RolledBack
        );
    }
    // an older v1 copy too
    let v1old = vec![v1(&h.p, &h.recs, 6, 10)];
    assert_eq!(
        assess(
            &h.leaves[..6],
            &v1old,
            &[anchor(&h.cps[2], false)],
            &pk(&h.p),
            false
        ),
        Verdict::RolledBack
    );
}
#[test]
fn c3_a2_records_cut_but_the_newest_checkpoint_kept_is_a_checkpoint_mismatch() {
    let h = honest();
    assert_eq!(
        assess(&h.leaves[..8], &h.cps, &[], &pk(&h.p), false),
        Verdict::CheckpointMismatch
    );
}
#[test]
fn c4_a3_a_lower_counter_at_the_same_size_is_rolled_back() {
    let h = honest();
    let shorter_chain = chain(&h.p, &h.leaves, &[3, 10], &[100, 300]); // counter 2 at size 10
    assert_eq!(
        assess(
            &h.leaves,
            &shorter_chain,
            &[anchor(&h.cps[2], false)],
            &pk(&h.p),
            false
        ),
        Verdict::RolledBack
    );
}
#[test]
fn c5_a4_a_copied_key_is_caught_only_when_a_signed_conflict_is_seen() {
    let h = honest();
    let (l, c) = alt_ledger(&h); // the copied key signs another history
    assert_eq!(assess(&l, &c, &[], &pk(&h.p), false), Verdict::OkUnanchored);
    assert_eq!(
        assess(&l, &c, &[anchor(&h.cps[2], true)], &pk(&h.p), false),
        Verdict::ForkDetected
    );
}
#[test]
fn c6_a5_clock_set_back_is_caught_by_the_v2_counter_only() {
    let h = honest();
    let back = chain(&h.p, &h.leaves, &[3, 6, 10], &[100, 300, 200]);
    assert_eq!(
        assess(&h.leaves, &back, &[], &pk(&h.p), false),
        Verdict::ClockRegression
    );
    let v1back = vec![v1(&h.p, &h.recs, 6, 300), v1(&h.p, &h.recs, 10, 200)];
    assert_eq!(
        assess(&h.leaves, &v1back, &[], &pk(&h.p), false),
        Verdict::OkUnanchored,
        "v1 has no counter: not detectable"
    );
}
#[test]
fn c7_a7_a_deleted_anchor_is_anchor_missing_when_one_is_expected() {
    let h = honest();
    assert_eq!(
        assess(&h.leaves, &h.cps, &[], &pk(&h.p), true),
        Verdict::AnchorMissing
    );
}
#[test]
fn c8_a_changed_record_with_the_old_checkpoints_is_a_checkpoint_mismatch() {
    let h = honest();
    let mut l = h.leaves.clone();
    l[4] = merkle::leaf_hash(b"changed");
    assert_eq!(
        assess(&l, &h.cps, &[], &pk(&h.p), false),
        Verdict::CheckpointMismatch
    );
}
#[test]
fn c9_signature_key_and_chain_faults_have_their_own_codes() {
    let h = honest();
    let mut bad = h.cps.clone();
    if let AnyCheckpoint::V2(c) = &mut bad[1] {
        c.signature = flip(&c.signature);
    }
    assert_eq!(
        assess(&h.leaves, &bad, &[], &pk(&h.p), false),
        Verdict::SignatureInvalid
    );
    let other = chain(&probe(2), &h.leaves, &[3, 6, 10], &[100, 200, 300]);
    assert_eq!(
        assess(&h.leaves, &other, &[], &pk(&h.p), false),
        Verdict::KeyChangedUnlogged
    );
    // a broken link: the second checkpoint is validly signed but names a wrong previous digest
    let root3 = merkle::root(&h.leaves[..3]).unwrap();
    let root6 = merkle::root(&h.leaves[..6]).unwrap();
    let first = sign_v2(&h.p, 1, &[0u8; 32], &root3, 3, 100).unwrap();
    let wrong_prev = sign_v2(&h.p, 2, &[9u8; 32], &root6, 6, 200).unwrap();
    let cps = vec![
        AnyCheckpoint::V2(first.clone()),
        AnyCheckpoint::V2(wrong_prev),
    ];
    assert_eq!(
        assess(&h.leaves[..6], &cps, &[], &pk(&h.p), false),
        Verdict::CheckpointMismatch
    );
    // a skipped counter
    let skip = sign_v2(&h.p, 3, &first.chain_digest(), &root6, 6, 200).unwrap();
    assert_eq!(
        assess(
            &h.leaves[..6],
            &[AnyCheckpoint::V2(first), AnyCheckpoint::V2(skip)],
            &[],
            &pk(&h.p),
            false
        ),
        Verdict::CheckpointMismatch
    );
}

// ---- precedence: ledgers that trip two conditions at once get the higher-precedence code
#[test]
fn d1_precedence_signature_before_key_before_mismatch_before_fork_before_rewritten_before_rolled_before_clock_before_missing(
) {
    let h = honest();
    let me = pk(&h.p);
    // signature_invalid beats checkpoint_mismatch
    let mut bad = h.cps.clone();
    if let AnyCheckpoint::V2(c) = &mut bad[2] {
        c.signature = flip(&c.signature);
    }
    assert_eq!(
        assess(&h.leaves[..8], &bad, &[], &me, false),
        Verdict::SignatureInvalid
    );
    // key_changed_unlogged beats checkpoint_mismatch
    let other = chain(&probe(2), &h.leaves, &[3, 6, 10], &[100, 200, 300]);
    assert_eq!(
        assess(&h.leaves[..8], &other, &[], &me, false),
        Verdict::KeyChangedUnlogged
    );
    // checkpoint_mismatch beats fork_detected (changed record AND a signed conflicting anchor)
    let (alt_l, alt_c) = alt_ledger(&h);
    let mut changed = alt_l.clone();
    changed[1] = merkle::leaf_hash(b"x");
    assert_eq!(
        assess(&changed, &alt_c, &[anchor(&h.cps[1], true)], &me, false),
        Verdict::CheckpointMismatch
    );
    // fork_detected beats rewritten_since_anchor (one signed and one hash-only anchor, both conflicting)
    let two = [anchor(&h.cps[0], false), anchor(&h.cps[1], true)];
    assert_eq!(
        assess(&alt_l, &alt_c, &two, &me, false),
        Verdict::ForkDetected
    );
    // rewritten_since_anchor beats rolled_back (one hash-only conflict at size 6, one anchor beyond the ledger)
    let far = Anchor {
        size: 20,
        root: [7u8; 32],
        counter: None,
        signed: None,
    };
    assert_eq!(
        assess(
            &alt_l,
            &alt_c,
            &[far.clone(), anchor(&h.cps[1], false)],
            &me,
            false
        ),
        Verdict::RewrittenSinceAnchor
    );
    // rolled_back beats clock_regression (a shorter ledger whose times also run backwards)
    let back = chain(&h.p, &h.leaves, &[3, 6], &[300, 200]);
    assert_eq!(
        assess(
            &h.leaves[..6],
            &back,
            &[anchor(&h.cps[2], false)],
            &me,
            false
        ),
        Verdict::RolledBack
    );
    // clock_regression beats anchor_missing
    let back_all = chain(&h.p, &h.leaves, &[3, 6, 10], &[100, 300, 200]);
    assert_eq!(
        assess(&h.leaves, &back_all, &[], &me, true),
        Verdict::ClockRegression
    );
}
#[test]
fn d2_ok_anchored_means_consistent_with_the_anchor_and_nothing_about_later_records() {
    // the records after the anchored size can be anything: only the checkpoints cover them
    let h = honest();
    let l = lv(&[recs("orig", 6), recs("late", 4)].concat());
    let c = chain(&h.p, &l, &[3, 6, 10], &[100, 200, 300]);
    assert_eq!(
        assess(&l, &c, &[anchor(&h.cps[1], false)], &pk(&h.p), false),
        Verdict::OkAnchored(6)
    );
}

// ---- no false alarms on unchanged ledgers
proptest! {
    #![proptest_config(ProptestConfig::with_cases(120))]
    #[test]
    fn e1_unchanged_ledgers_never_raise_an_alarm(n in 1usize..40, cuts in proptest::collection::vec(1usize..40, 1..5), use_v2 in any::<bool>(), take in 0usize..4, signed in any::<bool>()) {
        let p = probe(3);
        let r = recs("prop", n);
        let l = lv(&r);
        let mut sizes: Vec<usize> = cuts.iter().map(|c| 1 + c % n).collect();
        sizes.push(n);
        sizes.sort();
        sizes.dedup();
        let times: Vec<u64> = (0..sizes.len() as u64).map(|i| 1000 + i * 10).collect();
        let cps: Vec<AnyCheckpoint> = if use_v2 {
            chain(&p, &l, &sizes, &times)
        } else {
            sizes.iter().zip(&times).map(|(s, t)| v1(&p, &r, *s, *t)).collect()
        };
        let anchors: Vec<Anchor> = cps.iter().take(take).map(|c| anchor(c, signed)).collect();
        let v = assess(&l, &cps, &anchors, &pk(&p), false);
        match anchors.iter().map(|a| a.size).max() {
            None => prop_assert_eq!(v, Verdict::OkUnanchored),
            Some(m) => prop_assert_eq!(v, Verdict::OkAnchored(m)),
        }
    }
}

// ---- added after the first bite run (two mutants survived: records beyond the last checkpoint, and a signed anchor that is not verified)
#[test]
fn f1_records_beyond_the_newest_checkpoint_are_a_checkpoint_mismatch() {
    let h = honest();
    let mut l = h.leaves.clone();
    l.push(merkle::leaf_hash(b"appended without a checkpoint"));
    l.push(merkle::leaf_hash(b"and another"));
    assert_eq!(
        assess(&l, &h.cps, &[], &pk(&h.p), false),
        Verdict::CheckpointMismatch
    );
}
#[test]
fn f2_an_anchor_whose_signature_does_not_verify_is_treated_as_hash_only() {
    let h = honest();
    let (l, c) = alt_ledger(&h);
    // a forged "signed" anchor: the checkpoint is real but its signature is damaged
    let mut a = anchor(&h.cps[1], true);
    if let Some(AnyCheckpoint::V2(s)) = &mut a.signed {
        s.signature = flip(&s.signature);
    }
    assert_eq!(
        assess(&l, &c, &[a], &pk(&h.p), false),
        Verdict::RewrittenSinceAnchor,
        "no fork claim from a signature that does not verify"
    );
    // and one signed by another key
    let other = chain(&probe(2), &h.leaves, &[3, 6, 10], &[100, 200, 300]);
    let b = anchor(&other[1], true);
    assert_eq!(
        assess(&l, &c, &[b], &pk(&h.p), false),
        Verdict::RewrittenSinceAnchor
    );
}

// ---- slice 3: the transition from v1 to v2 and the downgrade rule
#[test]
fn g1_a_ledger_may_start_v1_and_continue_v2_but_a_v1_after_a_v2_is_a_checkpoint_mismatch() {
    let h = honest();
    let me = pk(&h.p);
    // v1 at sizes 3 and 6, then v2 (counter 1, prev zero: the chain starts at the switch) at 8 and 10
    let v1_part = vec![v1(&h.p, &h.recs, 3, 100), v1(&h.p, &h.recs, 6, 200)];
    let v2_part = chain(&h.p, &h.leaves, &[8, 10], &[300, 400]);
    let mixed: Vec<AnyCheckpoint> = [v1_part.clone(), v2_part.clone()].concat();
    assert_eq!(
        assess(&h.leaves, &mixed, &[], &me, false),
        Verdict::OkUnanchored,
        "v1 then v2 is allowed"
    );
    // downgrade: a v1 checkpoint after a v2 one
    let down: Vec<AnyCheckpoint> = [v2_part.clone(), vec![v1(&h.p, &h.recs, 10, 500)]].concat();
    assert_eq!(
        assess(&h.leaves, &down, &[], &me, false),
        Verdict::CheckpointMismatch,
        "a v1 after a v2 is refused"
    );
    // and the same downgrade in the middle of a longer ledger
    let mid: Vec<AnyCheckpoint> =
        [v1_part, v2_part.clone(), vec![v1(&h.p, &h.recs, 10, 600)]].concat();
    assert_eq!(
        assess(&h.leaves, &mid, &[], &me, false),
        Verdict::CheckpointMismatch
    );
}

// ---- added after the first mutation run (survivors: equal times, equal and shrinking sizes, the fork slot)
#[test]
fn h1_equal_checkpoint_times_are_fine_only_a_lower_time_is_a_regression() {
    let h = honest();
    let eq = chain(&h.p, &h.leaves, &[3, 6, 10], &[100, 100, 100]);
    assert_eq!(
        assess(&h.leaves, &eq, &[], &pk(&h.p), false),
        Verdict::OkUnanchored,
        "the writer repeats the time when an event is older"
    );
    let low = chain(&h.p, &h.leaves, &[3, 6, 10], &[100, 100, 99]);
    assert_eq!(
        assess(&h.leaves, &low, &[], &pk(&h.p), false),
        Verdict::ClockRegression
    );
}
#[test]
fn h2_a_v2_chain_may_repeat_a_size_with_a_new_counter_but_may_never_shrink() {
    let h = honest();
    let me = pk(&h.p);
    let same = chain(&h.p, &h.leaves, &[3, 3, 10], &[100, 200, 300]);
    assert_eq!(
        assess(&h.leaves, &same, &[], &me, false),
        Verdict::OkUnanchored
    );
    // every root is right and the last checkpoint covers the records: only the size order can show it
    let shrink = chain(&h.p, &h.leaves, &[3, 6, 4, 10], &[100, 200, 300, 400]);
    assert_eq!(
        assess(&h.leaves, &shrink, &[], &me, false),
        Verdict::CheckpointMismatch
    );
}
#[test]
fn h3_a_conflict_at_one_size_is_a_fork_even_when_the_counters_differ_and_a_conflict_at_one_counter_too(
) {
    let h = honest();
    let me = pk(&h.p);
    let (alt_l, _) = alt_ledger(&h);
    // the anchor is the original size 10 at counter 3; the rewritten ledger has ONE checkpoint, size 10, counter 1, another root
    let short = chain(&h.p, &alt_l, &[10], &[300]);
    assert_eq!(
        assess(&alt_l, &short, &[anchor(&h.cps[2], true)], &me, false),
        Verdict::ForkDetected,
        "same size, other counter"
    );
    // the same counter (2) at another size and another root: the key signed two checkpoints for one counter
    let other_sizes = chain(&h.p, &alt_l, &[4, 8, 10], &[100, 200, 300]);
    assert_eq!(
        assess(&alt_l, &other_sizes, &[anchor(&h.cps[1], true)], &me, false),
        Verdict::ForkDetected,
        "same counter, other size"
    );
    // no conflict when both the size and the counter differ and the anchor's root is consistent
    assert_eq!(
        assess(&h.leaves, &h.cps, &[anchor(&h.cps[0], true)], &me, false),
        Verdict::OkAnchored(3)
    );
}
