//! S7c: the scripted timeline and the token metadata, checked against an independent Python model of the
//! documented rules (the documented generator rules (not published)): record order, record times, checkpoint times,
//! witness times, and the seeded token counts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::transparency_log::decode_record;
use entropa_ledger::*;
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/generator_timeline_v1.json");

#[test]
fn t1_order_times_and_token_counts_match_the_independent_model() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let (seed, n, start) = (
            case["seed"].as_u64().unwrap(),
            case["scenarios"].as_u64().unwrap() as usize,
            case["start"].as_u64().unwrap(),
        );
        let mut g = generator(seed);
        let mut store = MemoryStore::default();
        must(g.run(&mut store, n, start));
        let bundle: Value = serde_json::from_str(&must(g.export_bundle(&store))).unwrap();
        let got: Vec<(String, u64)> = bundle["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["kind"].as_str().unwrap().to_string(),
                    r["ts"].as_u64().unwrap(),
                )
            })
            .collect();
        let want: Vec<(String, u64)> = case["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["kind"].as_str().unwrap().to_string(),
                    r["ts"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(got, want, "seed {seed}: record kinds and times");
        let cps: Vec<u64> = store.checkpoints().iter().map(|c| c.timestamp).collect();
        let want_cps: Vec<u64> = case["checkpoint_ts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_u64().unwrap())
            .collect();
        assert_eq!(cps, want_cps, "seed {seed}: checkpoint times");
        for (w, cp_ts) in store.witnesses().iter().zip(&cps) {
            assert_eq!(
                entropa_witness::decode_statement(w)
                    .unwrap()
                    .fields
                    .witness_time,
                cp_ts + 1,
                "witness time is checkpoint time + 1"
            );
        }
        let metas: Vec<(u64, u64, u64)> = (0..store.len())
            .filter_map(|i| {
                let (payload, _) = decode_record(&store.record(i).unwrap()).unwrap();
                decode_event(&payload)
                    .ok()
                    .and_then(|e| e.fields.agent)
                    .map(|a| (a.input_tokens, a.output_tokens, a.cost_micro_usd))
            })
            .collect();
        let want_metas: Vec<(u64, u64, u64)> = case["metas"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                (
                    m["input_tokens"].as_u64().unwrap(),
                    m["output_tokens"].as_u64().unwrap(),
                    m["cost_micro_usd"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(metas, want_metas, "seed {seed}: token metadata");
    }
}
