#![no_main]
use entropa_council::{plan_carryover, Candidate};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

// plan_carryover never panics; on success it partitions the candidates (nothing lost, nothing repeated), respects the
// cap, and does not depend on the order of the input.
fuzz_target!(|data: &[u8]| {
    let sev = ["low", "medium", "high", "hard_rule", "urgent"];
    let cands: Vec<Candidate> = data.chunks(2).take(40).map(|c| Candidate { id: format!("f-{}", c[0] % 50), severity: sev[usize::from(c.get(1).copied().unwrap_or(0)) % sev.len()].to_string() }).collect();
    let cap = usize::from(data.first().copied().unwrap_or(0) % 14);
    let Ok(plan) = plan_carryover(&cands, cap) else { return };
    let all: BTreeSet<&str> = plan.in_session.iter().chain(&plan.carried).map(String::as_str).collect();
    assert_eq!(all.len(), plan.in_session.len() + plan.carried.len());
    assert_eq!(all.len(), cands.len());
    assert!(plan.in_session.len() <= cap);
    let mut rev = cands.clone();
    rev.reverse();
    assert_eq!(plan_carryover(&rev, cap).ok(), Some(plan));
});
