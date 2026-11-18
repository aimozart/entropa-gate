//! Sliding-window rate limiter with an injected clock (milliseconds), so tests never sleep.

const WINDOW_MS: u64 = 60_000;
/// Calls per minute across all tools.
pub const OVERALL_LIMIT: usize = 30;
/// Calls per minute for `list_records`.
pub const LIST_RECORDS_LIMIT: usize = 10;

/// Which limit refused a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// 30 calls per minute across all tools.
    Overall,
    /// 10 calls per minute for `list_records`.
    ListRecords,
}

/// Admitted-call times. Only admitted calls are recorded, so refusals do not extend the wait.
#[derive(Debug, Default)]
pub struct Limiter {
    overall: Vec<u64>,
    list_records: Vec<u64>,
}

fn prune(v: &mut Vec<u64>, now: u64) {
    v.retain(|t| now.saturating_sub(*t) < WINDOW_MS);
}

fn retry_after_seconds(oldest: u64, now: u64) -> u64 {
    let wait_ms = (oldest + WINDOW_MS).saturating_sub(now);
    wait_ms.div_ceil(1000).max(1)
}

impl Limiter {
    /// Admit a call at `now_ms` (recording it) or return the limit hit and the seconds to wait.
    pub fn admit(&mut self, is_list_records: bool, now_ms: u64) -> Result<(), (Limit, u64)> {
        prune(&mut self.overall, now_ms);
        prune(&mut self.list_records, now_ms);
        if self.overall.len() >= OVERALL_LIMIT {
            let oldest = self.overall.first().copied().unwrap_or(now_ms);
            return Err((Limit::Overall, retry_after_seconds(oldest, now_ms)));
        }
        if is_list_records && self.list_records.len() >= LIST_RECORDS_LIMIT {
            let oldest = self.list_records.first().copied().unwrap_or(now_ms);
            return Err((Limit::ListRecords, retry_after_seconds(oldest, now_ms)));
        }
        self.overall.push(now_ms);
        if is_list_records {
            self.list_records.push(now_ms);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_is_exclusive_at_exactly_sixty_seconds() {
        let mut l = Limiter::default();
        for _ in 0..OVERALL_LIMIT {
            l.admit(false, 0).unwrap();
        }
        assert_eq!(l.admit(false, 59_999).unwrap_err().0, Limit::Overall);
        assert!(l.admit(false, 60_000).is_ok());
    }

    #[test]
    fn retry_after_is_at_least_one_second_and_rounds_up() {
        assert_eq!(retry_after_seconds(0, 59_999), 1);
        assert_eq!(retry_after_seconds(0, 30_000), 30);
        assert_eq!(retry_after_seconds(0, 30_001), 30);
    }

    #[test]
    fn list_records_has_its_own_smaller_budget() {
        let mut l = Limiter::default();
        for _ in 0..LIST_RECORDS_LIMIT {
            l.admit(true, 0).unwrap();
        }
        assert_eq!(l.admit(true, 1).unwrap_err().0, Limit::ListRecords);
        assert!(l.admit(false, 1).is_ok());
    }
}
