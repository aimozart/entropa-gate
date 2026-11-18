//! The synthetic scenario generator: deterministic, real crates, per-actor keys, no internal names.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_approvals::{decode, ActionClass, Body};
use entropa_core::transparency_log::{decode_record, TransparencyLog};
use entropa_ledger::*;
use serde_json::Value;
use std::collections::BTreeSet;

fn payloads(store: &MemoryStore) -> Vec<String> {
    (0..store.len())
        .map(|i| decode_record(&store.record(i).unwrap()).unwrap().0)
        .collect()
}

#[test]
fn g1_the_same_seed_gives_byte_identical_output_and_another_seed_does_not() {
    let (_, _, _, a) = run_mem(7, 12);
    let (_, _, _, b) = run_mem(7, 12);
    let (_, _, _, c) = run_mem(8, 12);
    assert_eq!(a, b, "same seed, same bundle");
    assert_ne!(a, c, "another seed, another bundle");
}

#[test]
fn g2_every_record_signature_verifies_and_the_bundle_is_self_consistent() {
    let (_, store, summary, bundle) = run_mem(1, 30);
    let report = must(verify_bundle(&bundle));
    assert_eq!(report.records, store.len());
    assert_eq!(report.receipts, store.len());
    assert_eq!(report.checkpoints, summary.checkpoints);
    assert_eq!(report.witnesses, summary.witnesses);
    assert!(
        report.signatures >= store.len(),
        "every record carries a signature that was checked"
    );
}

#[test]
fn g3_the_real_cedar_gate_decided_with_the_reference_policies() {
    let (g, store, summary, _) = run_mem(2, 30);
    let want = entropa_policy::Engine::new_bound(SCHEMA, POLICIES, g.directory())
        .unwrap()
        .policy_set_hash();
    let mut seen = 0;
    for p in payloads(&store) {
        let v: Value = serde_json::from_str(&p).unwrap();
        if v["type"] == "policy.decision" {
            assert_eq!(v["policy_set_hash"], want.as_str());
            assert_eq!(v["enforced"], true);
            seen += 1;
        }
    }
    assert!(seen >= 5, "policy decisions recorded: {seen}");
    assert!(summary.refused >= 1, "the gate refused something");
    assert!(
        summary.allowed >= 1,
        "the gate allowed something with a valid approval"
    );
}

fn approval_events(store: &MemoryStore) -> Vec<entropa_approvals::SignedEvent> {
    payloads(store)
        .iter()
        .filter_map(|p| decode(p).ok())
        .collect()
}

#[test]
fn g4_attestation_only_ever_opens_direction_and_the_replay_rejects_nothing() {
    let (g, store, _, _) = run_mem(3, 40);
    let events = approval_events(&store);
    assert!(!events.is_empty());
    let mut class_of = std::collections::HashMap::new();
    for e in &events {
        if let Body::Request { action_class, .. } = &e.event.body {
            class_of.insert(e.event.request_id.clone(), *action_class);
        }
    }
    let mut attested = 0;
    for e in &events {
        if let Body::Approve {
            on_behalf_of: Some(_),
            ..
        } = &e.event.body
        {
            attested += 1;
            let class = class_of[&e.event.request_id];
            assert_eq!(
                class,
                ActionClass::Direction,
                "an attestation approved {class:?}"
            );
        }
    }
    assert!(attested >= 1, "at least one attested direction approval");
    // replay the generated log with the real approvals crate
    let mut log = TransparencyLog::new();
    for i in 0..store.len() {
        log.append(&store.record(i).unwrap());
    }
    let state = entropa_approvals::replay(&log, &g.directory(), START + 10_000_000);
    assert!(
        state.rejected.is_empty(),
        "rejected: {:?}",
        state.rejected.len()
    );
}

#[test]
fn g5_all_three_tenants_and_all_scenario_kinds_appear() {
    let (_, _, summary, _) = run_mem(4, 30);
    for t in Tenant::ALL {
        assert!(
            summary.by_tenant.get(t.as_str()).copied().unwrap_or(0) >= 3,
            "{} {:?}",
            t.as_str(),
            summary.by_tenant
        );
    }
    let kinds: BTreeSet<&str> = summary.by_kind.keys().map(String::as_str).collect();
    for k in [
        "agent.invocation",
        "tx.screened",
        "directory.actor",
        "policy.decision",
        "approval.request",
        "approval.approve",
        "approval.deny",
        "approval.consume",
    ] {
        assert!(kinds.contains(k), "missing kind {k}: {kinds:?}");
    }
    assert_eq!(summary.by_kind.values().sum::<usize>(), summary.records);
}

#[test]
fn g6_every_checkpoint_gets_a_verifying_witness_statement_from_the_real_witness_crate() {
    let (_, store, summary, bundle) = run_mem(5, 20);
    assert!(summary.checkpoints >= 2);
    assert_eq!(summary.witnesses, summary.checkpoints);
    assert_eq!(store.witnesses().len(), summary.witnesses);
    assert_eq!(must(verify_bundle(&bundle)).witnesses, summary.witnesses);
    for w in store.witnesses() {
        let st = entropa_witness::decode_statement(&w).unwrap();
        assert_eq!(st.fields.log_id.len(), 64);
    }
}

#[test]
fn g7_nothing_public_names_the_crew_and_every_event_is_synthetic() {
    let (_, store, _, bundle) = run_mem(6, 30);
    lower_crew_free(&bundle);
    for p in payloads(&store) {
        lower_crew_free(&p);
        if let Ok(ev) = decode_event(&p) {
            let v: Value = serde_json::from_str(&encode_event(&ev).unwrap()).unwrap();
            assert_eq!(v["synthetic"], true);
        }
    }
}

#[test]
fn g8_timestamps_never_go_backwards_and_start_where_asked() {
    let (_, store, _, _) = run_mem(9, 20);
    let mut last = 0;
    let mut first = None;
    for p in payloads(&store) {
        let v: Value = serde_json::from_str(&p).unwrap();
        if let Some(ts) = v["ts"].as_u64() {
            first.get_or_insert(ts);
            assert!(ts >= last, "{ts} < {last}");
            last = ts;
        }
    }
    assert_eq!(first, Some(START));
}

#[test]
fn g9_a_second_run_extends_the_same_ledger_without_duplicating_the_directory() {
    let mut g = generator(11);
    let mut store = MemoryStore::default();
    must(g.run(&mut store, 8, START));
    let first_len = store.len();
    let first_cps = store.checkpoints().len();
    must(g.run(&mut store, 8, START + 100_000));
    assert!(store.len() > first_len);
    assert!(store.checkpoints().len() > first_cps);
    let dir_events = payloads(&store)
        .iter()
        .filter(|p| p.contains("\"kind\":\"directory.actor\""))
        .count();
    assert_eq!(
        dir_events,
        g.directory().actors.len(),
        "one directory event per registered actor"
    );
    must(verify_bundle(&must(g.export_bundle(&store))));
}

#[test]
fn g10_absurd_scenario_counts_are_refused() {
    let mut g = generator(1);
    let mut store = MemoryStore::default();
    assert!(matches!(
        expect_err(g.run(&mut store, 10_001, START)),
        LedgerError::Limit(_)
    ));
    assert_eq!(store.len(), 0, "nothing was written");
}

#[test]
fn g11_a_run_into_the_file_store_equals_a_run_into_memory() {
    let dir = tmpdir("gen-file");
    let mut g = generator(12);
    let mut fs_store = must(FileStore::open(&dir));
    must(g.run(&mut fs_store, 10, START));
    let file_bundle = must(g.export_bundle(&fs_store));
    let (_, _, _, mem_bundle) = run_mem(12, 10);
    assert_eq!(file_bundle, mem_bundle);
}
