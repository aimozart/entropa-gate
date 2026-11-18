//! Pure scheduling logic for periodic "I'm alive" logging, independent of whether
//! there was any real work to do that tick. Exists specifically to close the blind
//! spot that caused a real incident in the old N=3 quorum system: a validator that
//! silently stops making progress looks identical, in logs, to one that's idle but
//! fine, unless something logs on a fixed cadence regardless of activity. See
//! The project history 2026-08-25 "validator-3 silently stuck ~45 hours" entry.

pub fn should_emit(last_heartbeat_secs: u64, now_secs: u64, interval_secs: u64) -> bool {
    now_secs >= last_heartbeat_secs + interval_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_emit_before_the_interval_has_elapsed() {
        assert!(!should_emit(1_000, 1_010, 30));
    }

    #[test]
    fn emits_once_the_interval_has_fully_elapsed() {
        assert!(should_emit(1_000, 1_030, 30));
    }

    #[test]
    fn emits_well_past_the_interval() {
        assert!(should_emit(1_000, 5_000, 30));
    }

    #[test]
    fn does_not_emit_exactly_one_second_before_the_boundary() {
        assert!(!should_emit(1_000, 1_029, 30));
    }
}
