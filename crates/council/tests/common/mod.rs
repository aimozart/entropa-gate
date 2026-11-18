//! Shared helpers. All data is synthetic. Events are built from JSON, so the tests depend on the schema of
//! docs/ARCHITECTURE-COUNCIL.md section 6 and not on any struct layout.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub use entropa_council::*;
use serde_json::{json, Value};

pub const SID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const OTHER_SID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const NOW: u64 = 1_800_000_000;
pub const WEEK: u64 = 604_800;
pub const EXPIRES: u64 = NOW + WEEK;

pub fn must<T>(r: Result<T, CouncilError>) -> T {
    r.unwrap_or_else(|e| panic!("unexpected error: {e:?}"))
}

pub fn expect_err<T: std::fmt::Debug>(r: Result<T, CouncilError>) -> CouncilError {
    match r {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(e) => e,
    }
}

pub fn hex64(c: char) -> String {
    c.to_string().repeat(64)
}

/// The unsigned JSON of a valid event of `kind`; `over` overrides or adds fields (a JSON `null` value removes none, it sets null).
pub fn unsigned(kind: &str, over: Value) -> Value {
    let mut v = match kind {
        "session.opened" => {
            json!({"cadence":"weekly","trigger":"schedule","period_start":NOW-WEEK,"period_end":NOW,
            "window_hash":window_hash(&scope().refs()),"n_decisions":4,"expires":EXPIRES})
        }
        "finding.submitted" => {
            json!({"finding_id":"f-1","subject_ref":"idx:1","class":"missing_approval","severity":"high",
            "confidence":"medium","proposed_change":"test","evidence":[{"kind":"ledger_index","ref":"idx:1"}],
            "provider":"vertex","model_id":"gemini-flash","text_hash":null})
        }
        "report.submitted" => {
            json!({"n_findings":1,"findings_hash":findings_hash(&["f-1".to_string()])})
        }
        "rebuttal.submitted" => {
            json!({"finding_id":"f-1","stance":"disagree","counter":"policy_intended","evidence":[],
            "provider":"bedrock","model_id":"nova-lite","text_hash":null})
        }
        "packet.compiled" => {
            json!({"packet_hash":hex64('e'),"item_count":1,"findings_hash":findings_hash(&["f-1".to_string()]),
            "items":[{"finding_id":"f-1","check":"verified","recommendation":"accept"}],"text_hash":null})
        }
        "decision.recorded" => {
            json!({"finding_id":"f-1","decision":"accept","reason":"evidence_sufficient","change_kind":"test",
            "approval_ref":"appr-1","attested":false,"auth_ref":null})
        }
        "change.linked" => json!({"finding_id":"f-1","change_kind":"test","ref":"commit-abc123"}),
        "proof.recorded" => {
            json!({"finding_id":"f-1","policy_set_hash_before":hex64('1'),"policy_set_hash_after":hex64('2'),
            "replay_set_hash":hex64('3'),"n_replayed":50,"n_changed":4,"newly_denied":3,"newly_allowed":1})
        }
        "session.closed" => {
            json!({"closing":"all_decided","accepted":1,"rejected":0,"deferred":0,"pending":0})
        }
        "session.expired" => {
            json!({"closing":"expired_pending","accepted":0,"rejected":0,"deferred":0,"pending":1})
        }
        "outcome.recorded" => {
            json!({"decision_ref":"idx:1","outcome":"as_intended","delay_secs":3600,"source":"scenario_label"})
        }
        "precedent.referenced" => {
            json!({"decision_ref":"idx:1","index_hash":hex64('4'),"precedent_ids":["p1","p2"],"k":2,"followed":"yes"})
        }
        "evaluation.recorded" => {
            json!({"reviewer_provider":"vertex","reviewer_model_id":"gemini-flash","suite_hash":hex64('5'),
            "detection_permille":850,"detection_high_permille":900,"false_positive_permille":50,"hallucinations":0,
            "hindsight_gap_pp":2,"stability_permille":950,"injection_permille":1000})
        }
        "carryover.recorded" => {
            let carried = ["f-13".to_string(), "f-14".to_string()];
            json!({"n_candidates":14,"carried_ids":["f-13","f-14"],"carried_hash":findings_hash(&carried),"to_period_start":NOW+WEEK})
        }
        other => panic!("unknown kind {other}"),
    };
    let m = v.as_object_mut().unwrap();
    m.insert("v".into(), json!(1));
    m.insert("type".into(), json!(kind));
    m.insert("actor".into(), json!("0123456789abcdef"));
    m.insert("ts".into(), json!(NOW + 100));
    m.insert("alg".into(), json!("ML-DSA-65"));
    if !matches!(
        kind,
        "outcome.recorded" | "precedent.referenced" | "evaluation.recorded"
    ) {
        m.insert("session_id".into(), json!(SID));
    }
    if let Some(o) = over.as_object() {
        for (k, x) in o {
            m.insert(k.clone(), x.clone());
        }
    }
    v
}

pub const ALL_KINDS: [&str; 14] = [
    "session.opened",
    "finding.submitted",
    "report.submitted",
    "rebuttal.submitted",
    "packet.compiled",
    "decision.recorded",
    "change.linked",
    "proof.recorded",
    "session.closed",
    "session.expired",
    "outcome.recorded",
    "precedent.referenced",
    "evaluation.recorded",
    "carryover.recorded",
];

/// A signed-shaped payload (the signature is `ab..`: shape only; the decoder does not check it).
pub fn payload_of(v: &Value) -> String {
    let mut v = v.clone();
    v.as_object_mut()
        .unwrap()
        .insert("sig".into(), json!("abcdef0123456789"));
    v.to_string()
}

pub fn payload(kind: &str, over: Value) -> String {
    payload_of(&unsigned(kind, over))
}

pub fn ev(kind: &str, over: Value) -> Event {
    must(decode_event(&payload(kind, over)))
}

/// The in-window decisions under review: two by Nova-based agents (Bedrock), two by Gemini-based agents (Vertex).
pub struct TestScope(pub Scope);

pub fn scope() -> TestScope {
    TestScope(Scope {
        decisions: vec![
            ("idx:1".into(), Provider::Bedrock),
            ("idx:2".into(), Provider::Bedrock),
            ("idx:3".into(), Provider::Vertex),
            ("idx:4".into(), Provider::Vertex),
        ],
    })
}

impl TestScope {
    pub fn refs(&self) -> Vec<String> {
        self.0.decisions.iter().map(|(r, _)| r.clone()).collect()
    }
}

pub fn open_session() -> Session {
    must(Session::open(
        &ev("session.opened", json!({})),
        Role::Scheduler,
        &scope().0,
    ))
}

/// `n` findings f-1..f-n by a Gemini critic about the Nova-based decisions (idx:1 / idx:2 alternating).
pub fn finding(i: usize) -> Event {
    ev(
        "finding.submitted",
        json!({"finding_id": format!("f-{i}"), "subject_ref": format!("idx:{}", 1 + (i % 2)),
        "evidence": [{"kind":"ledger_index","ref": format!("idx:{}", 1 + (i % 2))}]}),
    )
}

pub fn ids(n: usize) -> Vec<String> {
    (1..=n).map(|i| format!("f-{i}")).collect()
}

/// Drive a session to the state just before the human decides: `n` findings, report, rebuttals, packet.
pub fn to_awaiting_decision(n: usize) -> Session {
    let mut s = open_session();
    for i in 1..=n {
        must(s.apply(&finding(i), Role::Critic, NOW + 100));
    }
    must(s.apply(
        &ev(
            "report.submitted",
            json!({"n_findings": n, "findings_hash": findings_hash(&ids(n))}),
        ),
        Role::Critic,
        NOW + 200,
    ));
    for i in 1..=n {
        must(s.apply(
            &ev(
                "rebuttal.submitted",
                json!({"finding_id": format!("f-{i}")}),
            ),
            Role::Contestor,
            NOW + 300,
        ));
    }
    let items: Vec<Value> = (1..=n).map(|i| json!({"finding_id": format!("f-{i}"), "check": "verified", "recommendation": "accept"})).collect();
    must(s.apply(
        &ev(
            "packet.compiled",
            json!({"item_count": n, "findings_hash": findings_hash(&ids(n)), "items": items}),
        ),
        Role::Orchestrator,
        NOW + 400,
    ));
    s
}

pub fn decide(s: &mut Session, i: usize, over: Value, at: u64) -> Result<(), CouncilError> {
    let mut o = json!({"finding_id": format!("f-{i}")});
    for (k, x) in over.as_object().unwrap() {
        o[k] = x.clone();
    }
    s.apply(&ev("decision.recorded", o), Role::Human, at)
}
