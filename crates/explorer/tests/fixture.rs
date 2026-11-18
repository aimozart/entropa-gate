//! The fixture bundle is exactly what the ledger generator produces (seed 1, 5 scenarios), so the golden
//! responses cannot silently drift from the real data. `ENTROPA_WRITE_FIXTURE=1` rewrites the file.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_ledger::{Generator, MemoryStore};

#[test]
fn f1_the_fixture_is_the_ledger_generators_output() {
    let mut g = Generator::new(1, SCHEMA, POLICIES).unwrap();
    let mut store = MemoryStore::default();
    g.run(&mut store, 5, 1_700_000_000).unwrap();
    let bundle = g.export_bundle(&store).unwrap();
    if std::env::var("ENTROPA_WRITE_FIXTURE").is_ok_and(|v| v == "1") {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/golden/bundle_seed1_n5.json"
            ),
            &bundle,
        )
        .unwrap();
        return;
    }
    assert_eq!(bundle, FIXTURE, "the fixture drifted: regenerate with ENTROPA_WRITE_FIXTURE=1 and re-run docs/evidence/s7d-gen-golden.py");
}
