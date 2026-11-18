//! Pure classification of a partner's submission rate into a volume tier -- the
//! signal for "this account has grown past self-serve-scale usage." Purely a
//! function of throughput (attestations per rolling hour), never company size or
//! lifetime total. The owner's explicit call, 2026-08-26: "it isnt enterprise vs
//! small biz... size of business is irrelevant" -- the number of transactions in
//! a fixed timeframe is the only thing that determines a tier crossing.
//!
//! Thresholds are grounded in the two real numbers this project has measured, not
//! a guess at company size: the live Pinnacle Financial account runs at roughly
//! ~180 attestations/hour from real, continuous multi-agent traffic, and
//! `entropa-ingest` was load-tested sustaining ~281 tx/sec (~1,000,000/hour)
//! before anything breaks. `Elevated`/`HighVolume` sit at 5x and 50x Pinnacle's
//! real current pace -- comfortably below the measured ceiling, but high enough
//! that crossing either is a genuine signal, not noise.

use std::collections::VecDeque;

const ONE_HOUR_SECS: u64 = 3600;

/// The `Base` variant is deliberately first (and therefore smallest under
/// `Ord`) so a plain `>` comparison between two tiers reliably detects a real
/// upward crossing, matching how `ProtoState::ingest` uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RateTier {
    #[default]
    Base,
    Elevated,
    HighVolume,
}

pub const ELEVATED_THRESHOLD_PER_HOUR: usize = 1_000;
pub const HIGH_VOLUME_THRESHOLD_PER_HOUR: usize = 10_000;

/// Classifies a rate already expressed as "attestations in the trailing hour."
pub fn classify_rate(attestations_last_hour: usize) -> RateTier {
    if attestations_last_hour >= HIGH_VOLUME_THRESHOLD_PER_HOUR {
        RateTier::HighVolume
    } else if attestations_last_hour >= ELEVATED_THRESHOLD_PER_HOUR {
        RateTier::Elevated
    } else {
        RateTier::Base
    }
}

/// Records a submission at `now` (unix seconds) and returns the genuine
/// attestations-in-the-last-hour count -- prunes anything outside the rolling
/// window first, so the count always reflects real recent throughput, not a
/// lifetime total.
pub fn record_and_count(timestamps: &mut VecDeque<u64>, now: u64) -> usize {
    timestamps.push_back(now);
    prune_older_than_one_hour(timestamps, now);
    timestamps.len()
}

fn prune_older_than_one_hour(timestamps: &mut VecDeque<u64>, now: u64) {
    while let Some(&oldest) = timestamps.front() {
        if now.saturating_sub(oldest) > ONE_HOUR_SECS {
            timestamps.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_rate_below_elevated_threshold_is_base() {
        assert_eq!(classify_rate(0), RateTier::Base);
        assert_eq!(classify_rate(999), RateTier::Base);
    }

    #[test]
    fn classify_rate_at_elevated_threshold_is_elevated() {
        assert_eq!(classify_rate(1_000), RateTier::Elevated);
        assert_eq!(classify_rate(9_999), RateTier::Elevated);
    }

    #[test]
    fn classify_rate_at_high_volume_threshold_is_high_volume() {
        assert_eq!(classify_rate(10_000), RateTier::HighVolume);
        assert_eq!(classify_rate(50_000), RateTier::HighVolume);
    }

    #[test]
    fn tier_ordering_lets_a_plain_greater_than_detect_an_upward_crossing() {
        assert!(RateTier::Elevated > RateTier::Base);
        assert!(RateTier::HighVolume > RateTier::Elevated);
        assert!(!(RateTier::Base > RateTier::Elevated));
    }

    #[test]
    fn record_and_count_keeps_entries_within_the_rolling_hour() {
        let mut timestamps = VecDeque::new();
        let now = 10_000u64;
        assert_eq!(record_and_count(&mut timestamps, now - 3000), 1);
        assert_eq!(record_and_count(&mut timestamps, now - 1000), 2);
        assert_eq!(record_and_count(&mut timestamps, now), 3);
    }

    #[test]
    fn record_and_count_prunes_entries_older_than_one_hour() {
        let mut timestamps = VecDeque::new();
        let now = 100_000u64;
        // Well outside the trailing hour relative to `now` below.
        timestamps.push_back(now - 7200);
        timestamps.push_back(now - 3700);
        assert_eq!(record_and_count(&mut timestamps, now), 1);
    }

    #[test]
    fn record_and_count_keeps_an_entry_exactly_at_the_one_hour_boundary() {
        let mut timestamps = VecDeque::new();
        let now = 100_000u64;
        timestamps.push_back(now - ONE_HOUR_SECS);
        assert_eq!(record_and_count(&mut timestamps, now), 2);
    }
}
