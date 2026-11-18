//! Per-client token bucket on an injected clock, with a bounded table.

use std::collections::{HashMap, VecDeque};

/// Tokens are counted in thousandths so a rate such as 60 per minute (one per second) stays exact.
const UNIT: u64 = 1_000;

struct Bucket {
    milli_tokens: u64,
    last: u64,
}

pub(crate) struct Limiter {
    refill_per_sec: u64,
    capacity: u64,
    max_clients: usize,
    buckets: HashMap<String, Bucket>,
    /// Insertion order; the oldest client is forgotten first when the table is full.
    order: VecDeque<String>,
}

impl Limiter {
    pub(crate) fn new(rate_per_minute: u32, burst: u32, max_clients: usize) -> Limiter {
        Limiter {
            refill_per_sec: (u64::from(rate_per_minute) * UNIT / 60).max(1),
            capacity: u64::from(burst) * UNIT,
            max_clients: max_clients.max(1),
            buckets: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub(crate) fn tracked(&self) -> usize {
        self.buckets.len()
    }

    /// Take one token for `client` at `now`; `Err(seconds)` says how long until one is available.
    pub(crate) fn take(&mut self, client: &str, now: u64) -> Result<(), u64> {
        if !self.buckets.contains_key(client) {
            while self.buckets.len() >= self.max_clients {
                match self.order.pop_front() {
                    Some(old) => {
                        self.buckets.remove(&old);
                    }
                    None => break,
                }
            }
            self.order.push_back(client.to_string());
            self.buckets.insert(
                client.to_string(),
                Bucket {
                    milli_tokens: self.capacity,
                    last: now,
                },
            );
        }
        let (refill, capacity) = (self.refill_per_sec, self.capacity);
        let Some(b) = self.buckets.get_mut(client) else {
            return Err(1);
        };
        // A clock that goes backwards mints nothing and is not followed.
        let elapsed = now.saturating_sub(b.last);
        b.last = b.last.max(now);
        b.milli_tokens = b
            .milli_tokens
            .saturating_add(elapsed.saturating_mul(refill))
            .min(capacity);
        if b.milli_tokens >= UNIT {
            b.milli_tokens -= UNIT;
            Ok(())
        } else {
            Err((UNIT - b.milli_tokens).div_ceil(refill).max(1))
        }
    }
}
