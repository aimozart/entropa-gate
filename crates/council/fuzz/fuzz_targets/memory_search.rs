#![no_main]
use entropa_council::{memory_hash, LexicalConfig, LexicalIndex, Precedent};
use libfuzzer_sys::fuzz_target;

// Building, searching and hashing never panic on arbitrary text. On success: at most k hits, best first, ties by id,
// every score at or above the threshold, only the asking tenant's precedents, the query order does not matter, and a
// revoked id never appears.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();
    let tenant = lines.next().unwrap_or("t1").to_string();
    let q: Vec<String> = lines.next().unwrap_or("").split(' ').map(str::to_string).collect();
    let k = usize::from(data.first().copied().unwrap_or(0) % 8);
    let precs: Vec<Precedent> = lines
        .take(12)
        .enumerate()
        .map(|(i, l)| Precedent {
            id: format!("p{i}"),
            tenant: if i % 2 == 0 { "t1" } else { "t2" }.to_string(),
            terms: l.split(' ').map(str::to_string).collect(),
        })
        .collect();
    let revoked = vec!["p0".to_string()];
    let config = LexicalConfig::default();
    let threshold = config.threshold;
    let Ok(idx) = LexicalIndex::build(config, precs.clone(), &revoked) else { return };
    assert_eq!(idx.index_hash().len(), 64);
    let Ok(hits) = idx.search(&tenant, &q, k) else { return };
    assert!(hits.len() <= k);
    for w in hits.windows(2) {
        assert!(w[0].score > w[1].score || (w[0].score == w[1].score && w[0].id < w[1].id));
    }
    for h in &hits {
        assert!(h.score >= threshold && h.score <= 1000);
        assert_ne!(h.id, "p0");
        let p = precs.iter().find(|p| p.id == h.id).expect("a hit is a precedent");
        assert_eq!(p.tenant, tenant);
    }
    let mut rev = q.clone();
    rev.reverse();
    assert_eq!(idx.search(&tenant, &rev, k).ok(), Some(hits.clone()));
    let ids: Vec<String> = hits.into_iter().map(|h| h.id).collect();
    if !ids.is_empty() {
        let _ = memory_hash(&idx.index_hash(), &ids);
    }
});
