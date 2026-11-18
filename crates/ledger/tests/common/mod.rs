//! Shared helpers. All data is synthetic. Demo keys come from public seeds and sign only synthetic events.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_core::Probe;
use entropa_ledger::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const SCHEMA: &str = include_str!("../../../../policies/entropa.cedarschema");
pub const POLICIES: &str = include_str!("../../../../policies/entropa.cedar");
pub const START: u64 = 1_700_000_000;
/// Crew names must never appear in public output (docs/ARCHITECTURE-EXPLORER.md section 8).
pub const CREW: [&str; 4] = ["spock", "scotty", "sulu", "captain"];

pub fn must<T>(r: Result<T, LedgerError>) -> T {
    match r {
        Ok(v) => v,
        Err(LedgerError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

pub fn expect_err<T: std::fmt::Debug>(r: Result<T, LedgerError>) -> LedgerError {
    match r {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(LedgerError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => e,
    }
}

/// A fresh directory name under the test temp dir. Container process ids repeat between runs, so the
/// name also carries the time in nanoseconds (a leftover directory from an earlier run is never reused).
pub fn tmpdir(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "ledger-{name}-{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ))
}

pub fn lower_crew_free(text: &str) {
    let t = text.to_lowercase();
    for c in CREW {
        assert!(!t.contains(c), "internal name {c:?} found in public output");
    }
}

pub fn generator(seed: u64) -> Generator {
    must(Generator::new(seed, SCHEMA, POLICIES))
}

/// True when `ENTROPA_FAST_TESTS=1` (set by scripts/mutants.sh for mutation runs only; check.sh and CI never set it).
pub fn fast_tests() -> bool {
    std::env::var("ENTROPA_FAST_TESTS").is_ok_and(|v| v == "1")
}

/// A scenario count: as asked, or at most 10 in the light mode (every scenario kind still appears within 6).
pub fn scenarios(n: usize) -> usize {
    if fast_tests() {
        n.min(10)
    } else {
        n
    }
}

/// A proptest case count: as asked, or at most 3 in the light mode.
pub fn cases(n: u32) -> u32 {
    if fast_tests() {
        n.min(3)
    } else {
        n
    }
}

/// Run the generator into a memory store; returns everything the tests look at.
pub fn run_mem(seed: u64, scenarios: usize) -> (Generator, MemoryStore, RunSummary, String) {
    let mut g = generator(seed);
    let mut store = MemoryStore::default();
    let summary = must(g.run(&mut store, self::scenarios(scenarios), START));
    let bundle = must(g.export_bundle(&store));
    (g, store, summary, bundle)
}

pub fn sample_fields(probe: &Probe) -> EventFields {
    EventFields {
        kind: Kind::TxScreened,
        tenant: Tenant::Bigironbank,
        key_id: entropa_approvals::key_id(&probe.pubkey_hex()),
        handle: Handle::AgentBigironbank,
        ts: START,
        subject_hash: hex::encode(blake3::hash(b"synthetic-tx-17").as_bytes()),
        label: LabelCode::FraudScreen,
        decision: Decision::Hold,
        reason: ReasonCode::NeedsReview,
        approval_ref: None,
        agent: Some(AgentMeta {
            provider: Provider::Fake,
            model_id: "amazon.nova-lite-v1:0".into(),
            input_tokens: 1200,
            output_tokens: 150,
            cost_micro_usd: 108,
        }),
        role: None,
        attested_by: None,
        pubkey_fingerprint: None,
        evidence: None,
    }
}
