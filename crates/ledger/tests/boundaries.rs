//! S7c: boundary and single-fault tests added after the first mutation run.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::transparency_log::{decode_record, encode_record, TransparencyLog};
use entropa_core::Probe;
use entropa_ledger::*;
use serde_json::{json, Value};
use std::fs;

type Tamper = Box<dyn Fn(&mut Value)>;

fn bundle_value(seed: u64, n: usize) -> (Generator, String) {
    let (g, _, _, b) = run_mem(seed, n);
    (g, b)
}

fn expect_verify_fail(v: &Value, name: &str) -> LedgerError {
    match verify_bundle(&v.to_string()) {
        Err(LedgerError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e @ (LedgerError::Verify(_) | LedgerError::Invalid(_))) => e,
        other => panic!("{name}: {other:?}"),
    }
}

#[test]
fn x1_store_edges() {
    let mut s = MemoryStore::default();
    assert!(s.is_empty());
    must(s.append(&vec![1u8; 64 * 1024]));
    assert!(!s.is_empty(), "a store with a record is not empty");
    assert!(matches!(
        s.append(&vec![1u8; 64 * 1024 + 1]),
        Err(LedgerError::Limit(_))
    ));
    // a checkpoint may be stored again (same size, same root)
    let probe = Probe::spawn();
    let mut log = TransparencyLog::new();
    log.append(&vec![1u8; 64 * 1024]);
    let cp = log.checkpoint(&probe, START);
    must(s.put_checkpoint(&cp));
    must(s.put_checkpoint(&cp));
    assert_eq!(s.checkpoints().len(), 2);
    // witness statements: exactly 64 KiB of JSON is fine, one more byte is not; newlines are not
    let pad = |total: usize| format!("{{\"p\":\"{}\"}}", "x".repeat(total - 8));
    must(s.put_witness(&pad(64 * 1024)));
    assert!(matches!(
        s.put_witness(&pad(64 * 1024 + 1)),
        Err(LedgerError::Invalid(_))
    ));
    assert!(matches!(
        s.put_witness("{\"a\":\n1}"),
        Err(LedgerError::Invalid(_))
    ));
}

#[test]
fn x2_the_file_store_refuses_torn_lines_that_look_complete_and_unreadable_files() {
    let dir = tmpdir("x2-torn");
    {
        let mut f = must(FileStore::open(&dir));
        must(f.append(b"rec-0"));
    }
    let path = dir.join("records.log");
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("7265632d31"); // a valid record in hex but without its newline: the write did not finish
    fs::write(&path, text).unwrap();
    assert!(matches!(
        expect_err(FileStore::open(&dir)),
        LedgerError::Corrupt(_)
    ));
    let dir2 = tmpdir("x2-dir");
    fs::create_dir_all(dir2.join("records.log")).unwrap(); // a directory where a file should be
    assert!(matches!(
        expect_err(FileStore::open(&dir2)),
        LedgerError::Io(_)
    ));
}

#[test]
fn x3_event_signature_length_edges() {
    let probe = Probe::spawn();
    let ev = must(sign_event(&probe, &sample_fields(&probe)));
    let payload = must(encode_event(&ev));
    let with_sig = |sig: String| {
        let mut v: Value = serde_json::from_str(&payload).unwrap();
        v["sig"] = json!(sig);
        v.to_string()
    };
    must(decode_event(&with_sig("ab".repeat(4096))));
    assert!(matches!(
        decode_event(&with_sig("ab".repeat(4097))),
        Err(LedgerError::Invalid(_))
    ));
    assert!(
        matches!(
            decode_event(&with_sig("abc".to_string())),
            Err(LedgerError::Invalid(_))
        ),
        "odd length"
    );
    must(decode_event(&with_sig("ab".to_string())));
}

#[test]
fn x4_directory_events_and_the_handle_map() {
    let (g, store, _, _) = run_mem(31, 6);
    assert_eq!(
        g.handles().len(),
        9,
        "the human principal and eight keyed actors"
    );
    let mut seen = 0;
    for i in 0..store.len() {
        let (payload, label) = decode_record(&store.record(i).unwrap()).unwrap();
        if label.as_deref() == Some("directory.actor") {
            let ev = decode_event(&payload).unwrap();
            let human = ev.fields.handle == Handle::HumanPrincipal;
            assert_eq!(
                ev.fields.attested_by,
                if human {
                    Some(Handle::OrchestratorAgent)
                } else {
                    None
                }
            );
            assert_eq!(
                ev.fields.role,
                Some(if human {
                    RoleCode::Human
                } else if matches!(
                    ev.fields.handle,
                    Handle::LogSigner | Handle::Generator | Handle::WitnessAzure
                ) {
                    RoleCode::Service
                } else {
                    RoleCode::Ai
                })
            );
            assert_eq!(
                ev.fields.pubkey_fingerprint.as_deref(),
                Some(ev.fields.key_id.as_str())
            );
            seen += 1;
        }
    }
    assert_eq!(seen, 9);
}

#[test]
fn x5_each_condition_of_the_bundle_checks_fails_on_its_own() {
    let (_, bundle) = bundle_value(32, 12);
    let base: Value = serde_json::from_str(&bundle).unwrap();
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "log algorithm",
            Box::new(|v| v["log"]["algorithm"] = json!("ML-DSA-44")),
        ),
        (
            "log fingerprint",
            Box::new(|v| v["log"]["fingerprint"] = json!("0123456789abcdef")),
        ),
        (
            "log key empty",
            Box::new(|v| v["log"]["pubkey_hex"] = json!("")),
        ),
        (
            "actor key id length",
            Box::new(|v| v["actors"][0]["key_id"] = json!("abc")),
        ),
        (
            "actor fingerprint differs",
            Box::new(|v| v["actors"][1]["fingerprint"] = json!("0123456789abcdef")),
        ),
        (
            "record kind only",
            Box::new(|v| v["records"][2]["kind"] = json!("tx.screened")),
        ),
        (
            "record tenant only",
            Box::new(|v| v["records"][12]["tenant"] = json!("entropa")),
        ),
        (
            "record handle only",
            Box::new(|v| v["records"][12]["handle"] = json!("builder-agent")),
        ),
        (
            "record ts only",
            Box::new(|v| v["records"][12]["ts"] = json!(5)),
        ),
        (
            "record summary only",
            Box::new(|v| v["records"][12]["summary"] = json!({"label": "x"})),
        ),
        (
            "record index",
            Box::new(|v| v["records"][4]["index"] = json!(40)),
        ),
        (
            "signer key blanked",
            Box::new(|v| {
                let i = v["actors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .position(|a| a["handle"] == "agent-bigironbank")
                    .unwrap();
                v["actors"][i]["pubkey_hex"] = json!("");
            }),
        ),
        (
            "consistency sizes",
            Box::new(|v| v["consistency"][0]["old_size"] = json!(1)),
        ),
        (
            "consistency proof element",
            Box::new(|v| v["consistency"][1]["proof"] = json!(["00".repeat(32)])),
        ),
        (
            "receipt index field",
            Box::new(|v| v["receipts"][3]["index"] = json!(2)),
        ),
    ];
    for (name, f) in cases {
        let mut v = base.clone();
        f(&mut v);
        expect_verify_fail(&v, name);
    }
    // the internal-name scan has its own message
    let mut v = base.clone();
    v["records"][0]["handle"] = json!("spock");
    match expect_verify_fail(&v, "internal") {
        LedgerError::Invalid(m) => assert!(m.contains("internal"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn x6_the_bundle_size_limit_is_exact_and_equal_size_checkpoints_are_allowed() {
    let (_, bundle) = bundle_value(33, 6);
    let pad = |total: usize| format!("{bundle}{}", " ".repeat(total - bundle.len()));
    must(verify_bundle(&pad(MAX_BUNDLE_BYTES)));
    assert!(matches!(
        verify_bundle(&pad(MAX_BUNDLE_BYTES + 1)),
        Err(LedgerError::Limit(_))
    ));
    // the same checkpoint listed twice, with an empty consistency entry between them, is still valid
    let mut v: Value = serde_json::from_str(&bundle).unwrap();
    let last = v["checkpoints"].as_array().unwrap().last().unwrap().clone();
    let size = last["size"].clone();
    v["checkpoints"].as_array_mut().unwrap().push(last);
    v["consistency"]
        .as_array_mut()
        .unwrap()
        .push(json!({"old_size": size, "new_size": size, "proof": []}));
    must(verify_bundle(&v.to_string()));
}

#[test]
fn x7_a_witness_statement_that_names_no_checkpoint_is_refused_even_when_validly_signed() {
    let (g, bundle) = bundle_value(34, 6);
    let keys = must(Keys::from_seed(34));
    let w = keys.probe(Handle::WitnessAzure).unwrap();
    let fields = entropa_witness::StatementFields {
        log_id: entropa_witness::log_id_for(&g.log_pubkey_hex()),
        size: 1,
        root: "00".repeat(32),
        log_timestamp: 1,
        witness_time: 2,
        previous_size: 0,
        previous_root: entropa_witness::NO_PREVIOUS_ROOT.to_string(),
        witness_pubkey: w.pubkey_hex(),
    };
    let digest =
        entropa_witness::statement_digest(&entropa_witness::statement_canonical_bytes(&fields));
    let sig = w.sign_hex(&digest);
    let statement = json!({"v": 1, "type": entropa_witness::STATEMENT_TYPE, "log_id": fields.log_id, "size": 1, "root": fields.root, "log_timestamp": 1,
        "witness_time": 2, "previous_size": 0, "previous_root": fields.previous_root, "witness_pubkey": fields.witness_pubkey, "sig": sig})
    .to_string();
    entropa_witness::verify_statement(&statement, &w.pubkey_hex()).unwrap();
    let mut v: Value = serde_json::from_str(&bundle).unwrap();
    v["witnesses"]
        .as_array_mut()
        .unwrap()
        .push(json!(statement));
    match expect_verify_fail(&v, "unrelated witness statement") {
        LedgerError::Verify(m) => assert!(m.contains("no checkpoint"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn x8_the_exporter_refuses_inconsistent_stores() {
    let (g, store, _, _) = run_mem(35, 6);
    // a record after the last checkpoint
    let mut more = MemoryStore::default();
    for i in 0..store.len() {
        must(more.append(&store.record(i).unwrap()));
    }
    for cp in store.checkpoints() {
        must(more.put_checkpoint(&cp));
    }
    must(more.append(&encode_record("{}", Some("tx.screened")).unwrap()));
    assert!(matches!(
        expect_err(g.export_bundle(&more)),
        LedgerError::Invalid(_)
    ));
    // an event whose handle does not belong to its key id
    let keys = must(Keys::from_seed(35));
    let bank = keys.probe(Handle::AgentBigironbank).unwrap();
    let mut f = sample_fields(bank);
    f.handle = Handle::AgentEntropa; // key id of the bank agent, handle of the entropa agent
    let payload = must(encode_event(&must(sign_event(bank, &f))));
    let mut crafted = MemoryStore::default();
    let rec = encode_record(&payload, Some("tx.screened")).unwrap();
    must(crafted.append(&rec));
    let mut log = TransparencyLog::new();
    log.append(&rec);
    must(crafted.put_checkpoint(&log.checkpoint(keys.probe(Handle::LogSigner).unwrap(), START)));
    assert!(matches!(
        expect_err(g.export_bundle(&crafted)),
        LedgerError::Invalid(_)
    ));
    // and a store with no checkpoint at all
    assert!(matches!(
        expect_err(g.export_bundle(&MemoryStore::default())),
        LedgerError::Invalid(_)
    ));
}

fn signed_statement(keys: &Keys, g: &Generator, size: u64, root: &str) -> String {
    let w = keys.probe(Handle::WitnessAzure).unwrap();
    let fields = entropa_witness::StatementFields {
        log_id: entropa_witness::log_id_for(&g.log_pubkey_hex()),
        size,
        root: root.to_string(),
        log_timestamp: 1,
        witness_time: 2,
        previous_size: 0,
        previous_root: entropa_witness::NO_PREVIOUS_ROOT.to_string(),
        witness_pubkey: w.pubkey_hex(),
    };
    let digest =
        entropa_witness::statement_digest(&entropa_witness::statement_canonical_bytes(&fields));
    json!({"v": 1, "type": entropa_witness::STATEMENT_TYPE, "log_id": fields.log_id, "size": size, "root": root, "log_timestamp": 1,
        "witness_time": 2, "previous_size": 0, "previous_root": fields.previous_root, "witness_pubkey": fields.witness_pubkey, "sig": w.sign_hex(&digest)})
    .to_string()
}

#[test]
fn x9_a_witness_statement_must_match_both_the_size_and_the_root_of_one_checkpoint() {
    let (g, bundle) = bundle_value(36, 6);
    let keys = must(Keys::from_seed(36));
    let base: Value = serde_json::from_str(&bundle).unwrap();
    let head_size = base["head"]["size"].as_u64().unwrap();
    let root_of_head = base["head"]["root"].as_str().unwrap().to_string();
    for (name, size, root) in [
        ("right size, wrong root", head_size, "00".repeat(32)),
        ("right root, wrong size", head_size + 1, root_of_head),
    ] {
        let mut v = base.clone();
        v["witnesses"]
            .as_array_mut()
            .unwrap()
            .push(json!(signed_statement(&keys, &g, size, &root)));
        match expect_verify_fail(&v, name) {
            LedgerError::Verify(m) => assert!(m.contains("no checkpoint"), "{name}: {m}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[test]
fn x10_two_checkpoints_of_the_same_size_must_have_the_same_root() {
    let (g, bundle) = bundle_value(37, 8);
    let keys = must(Keys::from_seed(37));
    let mut v: Value = serde_json::from_str(&bundle).unwrap();
    let size = v["checkpoints"][0]["size"].as_u64().unwrap() as usize;
    // a validly signed checkpoint of a forked history with the same number of records
    let mut fork = TransparencyLog::new();
    for i in 0..size {
        fork.append(format!("fork-{i}").as_bytes());
    }
    let forked = fork.checkpoint(keys.probe(Handle::LogSigner).unwrap(), START);
    assert_eq!(forked.size, size);
    assert_eq!(forked.proposer_pubkey, g.log_pubkey_hex());
    v["checkpoints"]
        .as_array_mut()
        .unwrap()
        .insert(0, serde_json::to_value(&forked).unwrap());
    v["consistency"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"old_size": size, "new_size": size, "proof": []}));
    expect_verify_fail(&v, "fork with the same size");
}

#[test]
fn x11_event_decoder_edges() {
    let probe = Probe::spawn();
    let payload = must(encode_event(&must(sign_event(
        &probe,
        &sample_fields(&probe),
    ))));
    // exactly 16 KiB of JSON (padded with whitespace) is read, one more byte is a limit error
    let pad = |total: usize| format!("{payload}{}", " ".repeat(total - payload.len()));
    must(decode_event(&pad(MAX_EVENT_BYTES)));
    assert!(matches!(
        decode_event(&pad(MAX_EVENT_BYTES + 1)),
        Err(LedgerError::Limit(_))
    ));
    // a signature of valid length that is not lowercase hex
    let with_sig = |sig: &str| {
        let mut v: Value = serde_json::from_str(&payload).unwrap();
        v["sig"] = json!(sig);
        v.to_string()
    };
    assert!(matches!(
        decode_event(&with_sig("zz")),
        Err(LedgerError::Invalid(_))
    ));
    assert!(matches!(
        decode_event(&with_sig(&"AB".repeat(40))),
        Err(LedgerError::Invalid(_))
    ));
    // directory fields: both role and fingerprint are required, and no model metadata is allowed
    let mut dir = sample_fields(&probe);
    dir.kind = Kind::DirectoryActor;
    dir.label = LabelCode::ActorRegistered;
    dir.agent = None;
    dir.role = Some(RoleCode::Ai);
    dir.pubkey_fingerprint = Some("0123456789abcdef".into());
    must(decode_event(&must(encode_event(&must(sign_event(
        &probe, &dir,
    ))))));
    let refused = |f: &dyn Fn(&mut EventFields)| {
        let mut x = dir.clone();
        f(&mut x);
        decode_event(&must(encode_event(&must(sign_event(&probe, &x))))).is_err()
    };
    assert!(refused(&|x| x.role = None), "fingerprint without a role");
    assert!(
        refused(&|x| x.pubkey_fingerprint = None),
        "role without a fingerprint"
    );
    assert!(
        refused(&|x| {
            x.agent = Some(AgentMeta {
                provider: Provider::Fake,
                model_id: "m".into(),
                input_tokens: 1,
                output_tokens: 1,
                cost_micro_usd: 1,
            })
        }),
        "model metadata on a directory event"
    );
    // non-directory events refuse each directory field on its own
    let plain = sample_fields(&probe);
    for f in [
        (|x: &mut EventFields| x.attested_by = Some(Handle::OrchestratorAgent))
            as fn(&mut EventFields),
        |x| x.pubkey_fingerprint = Some("0123456789abcdef".into()),
        |x| x.role = Some(RoleCode::Ai),
    ] {
        let mut x = plain.clone();
        f(&mut x);
        assert!(decode_event(&must(encode_event(&must(sign_event(&probe, &x))))).is_err());
    }
}
