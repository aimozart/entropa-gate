//! INS2 slice 3 red tests: the v2 writer path (`append_v2`) and `verify_ledger` for v2 and mixed ledgers. Fixed test seed; synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::anchor::{digest_v2, AnyCheckpoint, CheckpointV2};
use entropa_core::{verify_hex, Probe};
use entropa_ledger::{FileStore, Kind, LedgerStore};
use entropa_nodecore::{append, append_v2, decision_fields, verify_ledger, NodeError};
use std::path::PathBuf;

fn probe() -> Probe {
    Probe::from_signing_key_hex(&hex::encode([7u8; 32])).unwrap()
}
fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nodecore-v2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("ledger")).unwrap();
    d
}
fn req(n: u32, ts: u64) -> String {
    format!(
        r#"{{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"synthetic question {n}","output":"SELECT {n}","run_id":"run-v2-{n}","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":{n},"output_tokens":4,"cost_micro_usd":9,"ts":{ts}}}"#
    )
}
fn fields(n: u32, ts: u64) -> entropa_ledger::EventFields {
    decision_fields(&req(n, ts), &probe().pubkey_hex()).unwrap()
}
fn accept(k: Kind) -> bool {
    k == Kind::PlatinumDecision
}
fn pk() -> String {
    probe().pubkey_hex()
}
fn v2_lines(d: &std::path::Path) -> Vec<CheckpointV2> {
    std::fs::read_to_string(d.join("ledger/checkpoints.log"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn w1_append_v2_issues_counters_chain_links_and_verifiable_signatures() {
    let d = dir("w1");
    for n in 1..=3 {
        let r = append_v2(
            &d,
            "ledger",
            &probe(),
            &fields(n, 1_700_000_000 + u64::from(n)),
        )
        .unwrap();
        assert_eq!(r.size, u64::from(n));
    }
    let cps = v2_lines(&d);
    assert_eq!(
        cps.iter().map(|c| c.counter).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(cps[0].prev, [0u8; 32]);
    assert_eq!(cps[1].prev, cps[0].chain_digest());
    assert_eq!(cps[2].prev, cps[1].chain_digest());
    for c in &cps {
        let digest = digest_v2(c.counter, &c.prev, &c.root, c.size, c.timestamp);
        assert!(
            verify_hex(&pk(), &digest, &c.signature),
            "signature over the domain-tagged digest"
        );
    }
    assert_eq!(
        verify_ledger(&d, "ledger", accept, &pk()).unwrap(),
        "OK records=3 checkpoints=3"
    );
}
#[test]
fn w2_the_checkpoint_time_never_goes_backwards_even_when_an_event_time_does() {
    let d = dir("w2");
    for (n, ts) in [
        (1, 1_700_000_500u64),
        (2, 1_700_000_100),
        (3, 1_700_000_900),
    ] {
        append_v2(&d, "ledger", &probe(), &fields(n, ts)).unwrap();
    }
    let times: Vec<u64> = v2_lines(&d).iter().map(|c| c.timestamp).collect();
    assert_eq!(
        times,
        vec![1_700_000_500, 1_700_000_500, 1_700_000_900],
        "max(event time, previous checkpoint time)"
    );
}
#[test]
fn w3_a_ledger_may_start_v1_and_continue_v2_and_a_v1_writer_then_refuses() {
    let d = dir("w3");
    for n in 1..=2 {
        append(
            &d,
            "ledger",
            &probe(),
            &fields(n, 1_700_000_000 + u64::from(n)),
        )
        .unwrap();
    }
    append_v2(&d, "ledger", &probe(), &fields(3, 1_700_000_003)).unwrap();
    append_v2(&d, "ledger", &probe(), &fields(4, 1_700_000_004)).unwrap();
    let s = FileStore::open_read_only(&d.join("ledger")).unwrap();
    let kinds: Vec<&str> = s
        .any_checkpoints()
        .iter()
        .map(|c| {
            if matches!(c, AnyCheckpoint::V1(_)) {
                "v1"
            } else {
                "v2"
            }
        })
        .collect();
    assert_eq!(kinds, vec!["v1", "v1", "v2", "v2"]);
    let v2s = v2_lines_mixed(&d);
    assert_eq!(
        (v2s[0].counter, v2s[0].prev),
        (1, [0u8; 32]),
        "the chain starts at the switch"
    );
    assert_eq!(
        verify_ledger(&d, "ledger", accept, &pk()).unwrap(),
        "OK records=4 checkpoints=4"
    );
    let e = append(&d, "ledger", &probe(), &fields(5, 1_700_000_005)).unwrap_err();
    assert!(
        matches!(e, NodeError::Store(..)),
        "a v1 writer after v2 is a downgrade: {e:?}"
    );
    assert_eq!(
        FileStore::open_read_only(&d.join("ledger")).unwrap().len(),
        4,
        "nothing was added"
    );
}
fn v2_lines_mixed(d: &std::path::Path) -> Vec<CheckpointV2> {
    std::fs::read_to_string(d.join("ledger/checkpoints.log"))
        .unwrap()
        .lines()
        .filter(|l| l.contains("\"counter\""))
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
#[test]
fn w4_verify_ledger_rejects_a_damaged_v2_signature_and_names_the_checkpoint() {
    let d = dir("w4");
    for n in 1..=3 {
        append_v2(
            &d,
            "ledger",
            &probe(),
            &fields(n, 1_700_000_000 + u64::from(n)),
        )
        .unwrap();
    }
    let p = d.join("ledger/checkpoints.log");
    let original = std::fs::read_to_string(&p).unwrap();
    let damage = |line: usize| -> String {
        let mut lines: Vec<String> = original.lines().map(String::from).collect();
        let at = lines[line].find("\"signature\":\"").unwrap() + 16;
        let mut b = lines[line].clone().into_bytes();
        b[at] = if b[at] == b'0' { b'1' } else { b'0' };
        lines[line] = String::from_utf8(b).unwrap();
        lines.iter().map(|l| format!("{l}\n")).collect()
    };
    // the newest checkpoint: nothing links to it, so the ledger opens and the signature check names it
    std::fs::write(&p, damage(2)).unwrap();
    match verify_ledger(&d, "ledger", accept, &pk()) {
        Err(NodeError::Verify(m)) => {
            assert!(m.contains("checkpoint 2") && m.contains("signature"), "{m}")
        }
        other => panic!("{other:?}"),
    }
    // a middle checkpoint: the next one names the digest of the SIGNED checkpoint, so the chain breaks and the ledger does not open
    std::fs::write(&p, damage(1)).unwrap();
    assert!(matches!(
        verify_ledger(&d, "ledger", accept, &pk()),
        Err(NodeError::Store(..))
    ));
}

#[test]
fn w5_the_checkpoint_time_also_never_goes_below_the_last_v1_checkpoint_across_the_switch() {
    let d = dir("w5");
    append(&d, "ledger", &probe(), &fields(1, 1_700_000_900)).unwrap();
    append_v2(&d, "ledger", &probe(), &fields(2, 1_700_000_100)).unwrap();
    let t = v2_lines_mixed(&d)[0].timestamp;
    assert_eq!(
        t, 1_700_000_900,
        "the first v2 checkpoint is not earlier than the v1 one before it"
    );
}

#[test]
fn w6_a_record_of_a_kind_the_ledger_does_not_accept_or_with_a_label_that_differs_from_its_kind_fails_verification(
) {
    use entropa_core::transparency_log::{encode_record, TransparencyLog};
    use entropa_ledger::{encode_event, sign_event};
    let sign = |d: &std::path::Path, f: &entropa_ledger::EventFields, label: &str| {
        let payload = encode_event(&sign_event(&probe(), f).unwrap()).unwrap();
        let record = encode_record(&payload, Some(label)).unwrap();
        let mut store = FileStore::open(&d.join("ledger")).unwrap();
        let mut log = TransparencyLog::new();
        log.append(&record);
        let cp = log.checkpoint(&probe(), 1_700_000_000);
        store.append(&record).unwrap();
        store.put_checkpoint(&cp).unwrap();
    };
    // (a) a correctly labelled record of a kind this ledger does not take
    let a = dir("w6a");
    let ev = r#"{"kind":"evidence.change","label":"code_change","decision":"allow","reason":"within_limits","control":"hitrust_10_sdlc","total":1,"passed":1,"flagged":0,"detail":"synthetic","run_id":"0000000000000000000000000000000000000000000000000000000000000001","ts":1700000009}"#;
    let f = entropa_nodecore::evidence_event(ev, &pk()).unwrap();
    sign(&a, &f, f.kind.as_str());
    match verify_ledger(&a, "ledger", accept, &pk()) {
        Err(NodeError::Verify(m)) => assert!(m.contains("not an accepted kind"), "{m}"),
        other => panic!("{other:?}"),
    }
    // (b) an accepted kind whose record label says something else
    let b = dir("w6b");
    let f2 = fields(1, 1_700_000_001);
    sign(&b, &f2, "evidence.change");
    match verify_ledger(&b, "ledger", accept, &pk()) {
        Err(NodeError::Verify(m)) => assert!(m.contains("not an accepted kind"), "{m}"),
        other => panic!("{other:?}"),
    }
    // and the honest pair is accepted by the same helper
    let c = dir("w6c");
    sign(&c, &f2, f2.kind.as_str());
    assert!(verify_ledger(&c, "ledger", accept, &pk()).is_ok());
}
