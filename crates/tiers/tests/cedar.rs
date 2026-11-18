//! AT2 task 4 (Cedar): the tier policies and the adapter. The expected matrix is written from a stage record (not published) and the access-tiers plan: T0 reads the corpus; T1 reads and calls a
//! model; T2 also calls tools; T3 is not an AT2 tier (default deny). Cedar can only RESTRICT: the tier ceiling in the gate is code, and a permit-everything policy changes nothing there.
//! Evaluation errors and unparsable policies fail closed. Cedar must add under 1 ms p95 (asserted in the release profile).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tiers::cedar::{CedarPolicy, TIER_POLICIES};
use entropa_tiers::{
    Action, Decision, DenyCode, EgressGuard, Gate, Guard, Meter, OfflineVerifier, PolicyEngine,
    RecordSink, Request, Retrieval, TierRecord,
};
use entropa_tokens::{empty_revocations, issue_a, Claims, Tier, Trust};

const NOW: u64 = 1_800_000_000;
const CORPUS: &str = "00000000000000000000000000000000000000000000000000000000000000aa";

#[test]
fn c1_the_shipped_policies_permit_exactly_the_plan_matrix() {
    let p = CedarPolicy::tiers();
    for tier in [Tier::T0, Tier::T1, Tier::T2, Tier::T3] {
        for action in [Action::ReadCorpus, Action::CallModel, Action::CallTool] {
            let want = matches!(
                (tier, action),
                (Tier::T0, Action::ReadCorpus)
                    | (Tier::T1, Action::ReadCorpus)
                    | (Tier::T1, Action::CallModel)
                    | (Tier::T2, _)
            );
            let tool = (action == Action::CallTool).then_some("tool:search");
            assert_eq!(
                p.allows(tier, action, tool),
                Ok(want),
                "{tier:?} {action:?}"
            );
        }
    }
}

#[test]
fn c2_loading_is_strict_and_the_default_is_deny() {
    assert!(CedarPolicy::from_text("this is not cedar").is_err());
    assert!(
        CedarPolicy::from_text(&format!(
            "{TIER_POLICIES}\npermit(principal action resource);"
        ))
        .is_err(),
        "one bad policy refuses the whole set"
    );
    let empty = CedarPolicy::from_text("").unwrap();
    for tier in [Tier::T0, Tier::T1, Tier::T2, Tier::T3] {
        assert_eq!(
            empty.allows(tier, Action::ReadCorpus, None),
            Ok(false),
            "an empty policy set denies everything"
        );
    }
    // a forbid wins over a permit
    let with_forbid = CedarPolicy::from_text(&format!("{TIER_POLICIES}\nforbid(principal == Tier::\"t1\", action == Action::\"call_model\", resource);")).unwrap();
    assert_eq!(
        with_forbid.allows(Tier::T1, Action::CallModel, None),
        Ok(false)
    );
    assert_eq!(
        with_forbid.allows(Tier::T1, Action::ReadCorpus, None),
        Ok(true)
    );
}

#[test]
fn c3_the_policy_hash_names_the_text_in_force() {
    let a = CedarPolicy::tiers().policy_hash();
    assert_eq!(a.len(), 64);
    assert!(a.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(
        a,
        CedarPolicy::from_text(TIER_POLICIES).unwrap().policy_hash(),
        "the shipped text hashes the same"
    );
    let b = CedarPolicy::from_text(&format!("{TIER_POLICIES}\n// changed"))
        .unwrap()
        .policy_hash();
    assert_ne!(a, b);
}

#[test]
fn c4_an_evaluation_error_is_an_error_not_an_allow() {
    // integer overflow inside a condition is a Cedar evaluation error for that policy
    let p = CedarPolicy::from_text(
        "permit(principal, action, resource) when { 9223372036854775807 + 1 > 0 };",
    )
    .unwrap();
    assert!(
        p.allows(Tier::T2, Action::CallModel, None).is_err(),
        "the engine failure is reported (the gate turns it into a denial)"
    );
}

#[test]
fn c5_odd_tool_names_never_panic_and_are_judged_by_the_policy() {
    let p = CedarPolicy::tiers();
    for t in [
        "tool:search",
        "a\"b",
        "é",
        "",
        "a\\b",
        "x y",
        "\u{0}",
        &"t".repeat(5000),
        "}{;permit",
    ] {
        let r = p.allows(Tier::T2, Action::CallTool, Some(t));
        assert!(r.is_ok(), "{t:?}: {r:?}");
        assert_eq!(
            p.allows(Tier::T1, Action::CallTool, Some(t)),
            Ok(false),
            "T1 has no tools, whatever the name"
        );
    }
}

struct Fix;
impl EgressGuard for Fix {
    fn check(&self, _: Tier, _: &[u8]) -> Result<Guard, String> {
        Ok(Guard::Allow)
    }
}
impl Retrieval for Fix {
    fn read(&self, _: &str, _: &str) -> Result<Vec<u8>, String> {
        Ok(b"a".to_vec())
    }
}
impl Meter for Fix {
    fn spent(&self, _: &str) -> u64 {
        0
    }
    fn calls_last_minute(&self, _: &str, _: u64) -> u64 {
        0
    }
}
impl RecordSink for Fix {
    fn write(&self, _: &TierRecord) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn c6_cedar_cannot_loosen_the_code_ceiling_and_its_failure_denies() {
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    trust.add(&issuer.pubkey_hex());
    let v = OfflineVerifier {
        trust,
        audience: "node-1".into(),
        skew: 30,
        max_ttl: 3600,
        rev_max_age: 300,
        revocations: Some(empty_revocations(&issuer, NOW)),
    };
    let claims = |id: u64, tier| Claims {
        token_id: format!("{id:032x}"),
        subject: "s".into(),
        tier,
        corpora: vec![CORPUS.into()],
        actions: vec![
            "call_model".into(),
            "call_tool".into(),
            "read_corpus".into(),
            "tool:search".into(),
        ],
        spend_cap: 1000,
        rate_cap: 10,
        not_before: NOW - 10,
        expiry: NOW + 600,
        audience: "node-1".into(),
        parent: None,
    };
    let all = CedarPolicy::from_text("permit(principal, action, resource);").unwrap();
    let gate = |p: &dyn PolicyEngine| -> Decision {
        let _ = p;
        Decision::Allowed
    };
    let _ = gate;
    let run = |p: &CedarPolicy, tier: Tier, action: &str, id: u64| {
        let r = Request {
            token: issue_a(&issuer, &claims(id, tier)).unwrap(),
            action: action.into(),
            corpus: Some(CORPUS.into()),
            tool: Some("tool:search".into()),
            cost: 1,
            payload: b"x".to_vec(),
            text: "t".into(),
            ..Request::default()
        };
        Gate {
            verifier: &v,
            policy: p,
            egress: &Fix,
            retrieval: &Fix,
            meter: &Fix,
            sink: &Fix,
        }
        .decide(&r, NOW)
        .decision
    };
    assert_eq!(
        run(&all, Tier::T0, "call_model", 1),
        Decision::Denied(DenyCode::TierForbids),
        "a permit-everything policy does not give T0 a model"
    );
    assert_eq!(
        run(&all, Tier::T0, "call_tool", 2),
        Decision::Denied(DenyCode::TierForbids)
    );
    assert_eq!(
        run(&all, Tier::T1, "call_tool", 3),
        Decision::Denied(DenyCode::TierForbids)
    );
    assert_eq!(
        run(&all, Tier::T3, "call_model", 4),
        Decision::Denied(DenyCode::TierForbids)
    );
    assert_eq!(
        run(&CedarPolicy::tiers(), Tier::T2, "call_tool", 5),
        Decision::Allowed,
        "the shipped policies allow what the plan allows"
    );
    let broken = CedarPolicy::from_text(
        "permit(principal, action, resource) when { 9223372036854775807 + 1 > 0 };",
    )
    .unwrap();
    assert_eq!(
        run(&broken, Tier::T2, "call_model", 6),
        Decision::Denied(DenyCode::PolicyError)
    );
    assert_eq!(
        run(
            &CedarPolicy::from_text("").unwrap(),
            Tier::T2,
            "call_model",
            7
        ),
        Decision::Denied(DenyCode::PolicyDenied),
        "an empty policy denies"
    );
}

#[test]
fn c7_cedar_adds_under_one_millisecond_at_p95() {
    let p = CedarPolicy::tiers();
    let mut ms: Vec<f64> = Vec::new();
    for i in 0..5000 {
        let (tier, action, tool) = [
            (Tier::T0, Action::ReadCorpus, None),
            (Tier::T1, Action::CallModel, None),
            (Tier::T2, Action::CallTool, Some("tool:search")),
            (Tier::T3, Action::CallModel, None),
        ][i % 4];
        let t = std::time::Instant::now();
        let _ = p.allows(tier, action, tool);
        ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    ms.sort_by(f64::total_cmp);
    let (p50, p95) = (ms[ms.len() / 2], ms[ms.len() * 95 / 100]);
    eprintln!("cedar decision p50 {p50:.4} ms p95 {p95:.4} ms (5000 runs)");
    if !cfg!(debug_assertions) {
        assert!(p95 < 1.0, "p95 {p95} ms");
    }
}

#[test]
fn c8_the_adapter_holds_no_clock_no_network_and_no_key_material() {
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cedar.rs")).unwrap();
    for bad in [
        "SystemTime",
        "Instant",
        "std::net",
        "TcpStream",
        "std::env",
        "std::process",
        "std::fs",
        "sign_hex",
        "Probe",
    ] {
        assert!(!src.contains(bad), "{bad} in cedar.rs");
    }
}
