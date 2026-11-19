//! Event schema: closed codes, strict decoder, signing, golden vectors, public naming rule.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_core::Probe;
use entropa_ledger::*;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("vectors/ledger_event_v1.json");

#[test]
fn e1_golden_vectors_match_an_independent_implementation() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 3);
    for c in cases {
        let f = &c["fields"];
        let agent = f["agent"].as_object().map(|a| AgentMeta {
            provider: Provider::parse(a["provider"].as_str().unwrap())
                .unwrap_or_else(|| panic!("{NOT_IMPLEMENTED}")),
            model_id: a["model_id"].as_str().unwrap().into(),
            input_tokens: a["input_tokens"].as_u64().unwrap(),
            output_tokens: a["output_tokens"].as_u64().unwrap(),
            cost_micro_usd: a["cost_micro_usd"].as_u64().unwrap(),
        });
        let parse = |k: &str| f[k].as_str().map(str::to_string);
        let fields = EventFields {
            kind: Kind::parse(f["kind"].as_str().unwrap())
                .unwrap_or_else(|| panic!("{NOT_IMPLEMENTED}")),
            tenant: Tenant::parse(f["tenant"].as_str().unwrap()).unwrap(),
            key_id: f["key_id"].as_str().unwrap().into(),
            handle: Handle::parse(f["handle"].as_str().unwrap()).unwrap(),
            ts: f["ts"].as_u64().unwrap(),
            subject_hash: f["subject_hash"].as_str().unwrap().into(),
            label: LabelCode::parse(f["label"].as_str().unwrap()).unwrap(),
            decision: Decision::parse(f["decision"].as_str().unwrap()).unwrap(),
            reason: ReasonCode::parse(f["reason"].as_str().unwrap()).unwrap(),
            approval_ref: parse("approval_ref"),
            agent,
            role: parse("role").and_then(|r| RoleCode::parse(&r)),
            attested_by: parse("attested_by").and_then(|h| Handle::parse(&h)),
            pubkey_fingerprint: parse("pubkey_fingerprint"),
            evidence: None,
        };
        let canon = event_canonical_bytes(&fields);
        if canon.is_empty() {
            panic!("{NOT_IMPLEMENTED}");
        }
        let name = c["name"].as_str().unwrap();
        assert_eq!(
            String::from_utf8(canon.clone()).unwrap(),
            c["canonical"].as_str().unwrap(),
            "{name}: canonical bytes"
        );
        assert_eq!(
            hex::encode(event_digest(&canon)),
            c["digest_hex"].as_str().unwrap(),
            "{name}: digest"
        );
    }
}

#[test]
fn e2_sign_encode_decode_verify_round_trip() {
    let probe = Probe::spawn();
    let f = sample_fields(&probe);
    let ev = must(sign_event(&probe, &f));
    let payload = must(encode_event(&ev));
    assert!(payload.len() < MAX_EVENT_BYTES);
    assert_eq!(must(decode_event(&payload)), ev);
    assert_eq!(must(verify_event(&payload, &probe.pubkey_hex())), ev);
    // canonical: keys sorted, no whitespace, the constant fields present
    let v: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(v["type"], EVENT_TYPE);
    assert_eq!(v["synthetic"], true);
    assert_eq!(v["v"], 1);
    assert!(!payload.contains(' '));
}

#[test]
fn e3_the_vocabularies_are_closed_and_exactly_these() {
    fn words<T: Copy>(all: &[T], f: impl Fn(T) -> &'static str) -> Vec<&'static str> {
        all.iter().map(|x| f(*x)).collect()
    }
    assert_eq!(
        words(Tenant::ALL, Tenant::as_str),
        ["entropa", "bigironbank", "hippagrchealthcare"]
    );
    assert_eq!(
        words(Kind::ALL, Kind::as_str),
        [
            "agent.invocation",
            "tx.screened",
            "directory.actor",
            "platinum.decision",
            "evidence.pipeline_run",
            "evidence.control_check",
            "evidence.access",
            "evidence.change",
            "evidence.policy",
            "council.step"
        ]
    );
    assert_eq!(
        words(LabelCode::ALL, LabelCode::as_str),
        [
            "fraud_screen",
            "case_review",
            "audit_question",
            "actor_registered",
            "nl_query",
            "ml_score",
            "rag_answer",
            "bronze",
            "silver",
            "gold",
            "platinum",
            "rls_test",
            "masking_check",
            "k_anonymity",
            "canary_scan",
            "identifier_range",
            "secret_scan",
            "ci_tests",
            "table_read",
            "deploy",
            "rollback",
            "schema_change",
            "key_rotation",
            "policy_approved",
            "code_change",
            "council_session",
            "council_packet",
            "council_finding",
            "council_rebuttal",
            "council_decision",
            "claims_triage",
            "policy_verdict",
            "approval_requested",
            "approval_denied",
            "case_outcome",
            "crypto_inventory",
            "log_integrity_check",
            "corpus_version",
            "retrieval_record",
            // Test change (TH1): one additive label, appended last
            "prereg_committed"
        ]
    );
    assert_eq!(
        words(Decision::ALL, Decision::as_str),
        ["allow", "deny", "hold", "escalate", "release", "info"]
    );
    assert_eq!(
        words(ReasonCode::ALL, ReasonCode::as_str),
        [
            "none",
            "policy_deny",
            "gate_pending",
            "gate_denied",
            "human_required",
            "within_limits",
            "needs_review",
            "cited_receipts",
            "guard_passed",
            "guard_refused",
            "injection_suspected",
            "check_passed",
            "check_failed",
            "council_accepted",
            "council_rejected",
            "council_deferred",
            "council_no_quorum"
        ]
    );
    assert_eq!(
        words(Provider::ALL, Provider::as_str),
        ["bedrock", "vertex", "fake", "local", "sparkml", "azure"]
    );
    assert_eq!(
        words(RoleCode::ALL, RoleCode::as_str),
        ["human", "ai", "service"]
    );
    assert_eq!(
        words(Handle::ALL, Handle::as_str),
        [
            "human-principal",
            "orchestrator-agent",
            "builder-agent",
            "operator-agent",
            "log-signer",
            "generator",
            "witness-azure",
            "cosigner-aws-kms",
            "agent-entropa",
            "agent-bigironbank",
            "agent-hippagrchealthcare",
            "critic-agent",
            "contestor-agent",
            "observer-agent",
            "scheduler-agent"
        ]
    );
    if Handle::parse("human-principal").is_none() {
        panic!("{NOT_IMPLEMENTED}");
    }
    for h in Handle::ALL {
        assert_eq!(Handle::parse(h.as_str()), Some(*h));
    }
    // internal names, wrong case and near misses are not handles
    for bad in [
        "spock",
        "the reviewer",
        "scotty",
        "sulu",
        "captain",
        "the owner",
        "HUMAN-PRINCIPAL",
        "human_principal",
        "builder-agent ",
        "",
        "agent-other",
    ] {
        assert_eq!(Handle::parse(bad), None, "{bad:?}");
    }
    for bad in ["Entropa", "bank", "", "entropa "] {
        assert_eq!(Tenant::parse(bad), None, "{bad:?}");
    }
}

fn good_payload() -> (String, Probe) {
    let probe = Probe::spawn();
    let ev = must(sign_event(&probe, &sample_fields(&probe)));
    (must(encode_event(&ev)), probe)
}

fn mutate(payload: &str, f: impl Fn(&mut Value)) -> String {
    let mut v: Value = serde_json::from_str(payload).unwrap();
    f(&mut v);
    v.to_string()
}

#[test]
fn e4_the_decoder_is_strict_and_never_echoes_input() {
    let (p, _) = good_payload();
    let cases: Vec<(&str, String)> = vec![
        ("unknown field", mutate(&p, |v| v["extra"] = json!(1))),
        (
            "missing sig",
            mutate(&p, |v| {
                v.as_object_mut().unwrap().remove("sig");
            }),
        ),
        (
            "missing kind",
            mutate(&p, |v| {
                v.as_object_mut().unwrap().remove("kind");
            }),
        ),
        (
            "wrong type",
            mutate(&p, |v| v["type"] = json!("explorer.other")),
        ),
        ("version 2", mutate(&p, |v| v["v"] = json!(2))),
        (
            "synthetic false",
            mutate(&p, |v| v["synthetic"] = json!(false)),
        ),
        (
            "synthetic missing",
            mutate(&p, |v| {
                v.as_object_mut().unwrap().remove("synthetic");
            }),
        ),
        (
            "kind outside the list",
            mutate(&p, |v| v["kind"] = json!("tx.free_text")),
        ),
        (
            "tenant outside the list",
            mutate(&p, |v| v["tenant"] = json!("acme")),
        ),
        (
            "handle is an internal name",
            mutate(&p, |v| v["handle"] = json!("spock")),
        ),
        (
            "label is free text",
            mutate(&p, |v| v["label"] = json!("customer John Smith paid rent")),
        ),
        (
            "decision free text",
            mutate(&p, |v| v["decision"] = json!("maybe later")),
        ),
        (
            "reason free text",
            mutate(&p, |v| v["reason"] = json!("<script>alert(1)</script>")),
        ),
        (
            "uppercase key id",
            mutate(&p, |v| v["key_id"] = json!("ABCDEF0123456789")),
        ),
        (
            "short key id",
            mutate(&p, |v| v["key_id"] = json!("abcdef")),
        ),
        (
            "uppercase subject hash",
            mutate(&p, |v| v["subject_hash"] = json!("AB".repeat(32))),
        ),
        (
            "approval_ref bad",
            mutate(&p, |v| v["approval_ref"] = json!("xyz")),
        ),
        (
            "ts as string",
            mutate(&p, |v| v["ts"] = json!("1700000000")),
        ),
        ("ts 2^53", mutate(&p, |v| v["ts"] = json!(1u64 << 53))),
        (
            "negative tokens",
            mutate(&p, |v| v["agent"]["input_tokens"] = json!(-1)),
        ),
        (
            "provider outside the list",
            mutate(&p, |v| v["agent"]["provider"] = json!("other")),
        ),
        (
            "model id with a space",
            mutate(&p, |v| v["agent"]["model_id"] = json!("a b")),
        ),
        (
            "model id too long",
            mutate(&p, |v| v["agent"]["model_id"] = json!("a".repeat(65))),
        ),
        (
            "agent extra field",
            mutate(&p, |v| v["agent"]["prompt"] = json!("hello")),
        ),
        (
            "uppercase sig",
            mutate(&p, |v| v["sig"] = json!("AB".repeat(40))),
        ),
        ("empty sig", mutate(&p, |v| v["sig"] = json!(""))),
        ("not an object", "[]".to_string()),
        ("not json", "{".to_string()),
    ];
    for (name, s) in cases {
        match decode_event(&s) {
            Err(LedgerError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
            Err(LedgerError::Invalid(m)) | Err(LedgerError::Limit(m)) => {
                for echoed in [
                    "John Smith",
                    "<script>",
                    "maybe later",
                    "1700000000",
                    "spock",
                ] {
                    assert!(
                        !m.contains(echoed),
                        "{name}: the error echoes the input ({echoed})"
                    );
                }
            }
            other => panic!("{name}: {other:?}"),
        }
    }
    let big = format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_EVENT_BYTES));
    assert!(matches!(decode_event(&big), Err(LedgerError::Limit(_))));
}

#[test]
fn e5_a_directory_event_carries_its_extra_fields_and_other_kinds_must_not() {
    let probe = Probe::spawn();
    let mut f = sample_fields(&probe);
    f.kind = Kind::DirectoryActor;
    f.label = LabelCode::ActorRegistered;
    f.decision = Decision::Info;
    f.reason = ReasonCode::None;
    f.agent = None;
    f.role = Some(RoleCode::Human);
    f.attested_by = Some(Handle::OrchestratorAgent);
    f.pubkey_fingerprint = Some("0123456789abcdef".into());
    f.handle = Handle::HumanPrincipal;
    let ev = must(sign_event(&probe, &f));
    must(decode_event(&must(encode_event(&ev))));
    // a tx.screened event with a role set is refused
    let mut bad = sample_fields(&probe);
    bad.role = Some(RoleCode::Ai);
    let payload = must(encode_event(&must(sign_event(&probe, &bad))));
    assert!(matches!(
        decode_event(&payload),
        Err(LedgerError::Invalid(_))
    ));
}

#[test]
fn e6_tampering_and_the_wrong_key_fail_verification() {
    let (p, probe) = good_payload();
    must(verify_event(&p, &probe.pubkey_hex()));
    let other = Probe::spawn();
    assert!(matches!(
        verify_event(&p, &other.pubkey_hex()),
        Err(LedgerError::Verify(_))
    ));
    for (name, s) in [
        ("decision", mutate(&p, |v| v["decision"] = json!("allow"))),
        ("ts", mutate(&p, |v| v["ts"] = json!(5))),
        ("tenant", mutate(&p, |v| v["tenant"] = json!("entropa"))),
        (
            "tokens",
            mutate(&p, |v| v["agent"]["output_tokens"] = json!(1)),
        ),
    ] {
        assert!(
            matches!(
                verify_event(&s, &probe.pubkey_hex()),
                Err(LedgerError::Verify(_))
            ),
            "{name}"
        );
    }
}
