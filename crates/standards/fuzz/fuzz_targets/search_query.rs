#![no_main]
mod common;
use entropa_standards::retrieve::{Config, Verdict};
use libfuzzer_sys::fuzz_target;

// Any bytes as a query (lossy UTF-8 and the exact text when valid), any of four configurations: the retriever never panics, never returns more
// than ten passages, marks every passage untrusted, and abstains with no passage.
fuzz_target!(|data: &[u8]| {
    let (sel, rest) = data.split_first().map_or((0, data), |(s, r)| (*s, r));
    let q = String::from_utf8_lossy(rest).into_owned();
    let cfg = Config {
        unindexed_guard: sel & 1 != 0,
        structural_flags: sel & 2 != 0,
        entity_guard: sel & 4 != 0,
        foreign_guard: sel & 8 != 0,
        ..Config::default()
    };
    let r = common::retriever().search(&q, Some("fz"), usize::from(sel >> 4), &cfg);
    assert!(r.passages.len() <= 10);
    assert!(r.passages.iter().all(|p| p.untrusted));
    assert!(r.verdict == Verdict::Answered || r.passages.is_empty());
    for p in &r.passages {
        if p.tier == entropa_standards::corpus::Tier::Licensed {
            assert!(p.text.is_none());
            assert!(p.quote.as_ref().is_some_and(|q| q.split_whitespace().count() <= 25));
        }
    }
});
